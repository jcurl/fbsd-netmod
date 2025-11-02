#include "ethtransmit.h"
#include <net/ethernet.h>
#include <net/if_dl.h>

// Import in_cksum_hdr(). Without in.h, ip.h, then the function isn't
// exposed.
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <machine/in_cksum.h>

#define MTULEN 1500

#define ETH_DST_MAC_OFFSET 0
#define ETH_SRC_MAC_OFFSET (ETH_DST_MAC_OFFSET + ETHER_ADDR_LEN)
#define ETH_PROTO_OFFSET   (ETH_SRC_MAC_OFFSET + ETHER_ADDR_LEN)
#define ETH_PAYLOAD_OFFSET ETHER_HDR_LEN

#define ETH_PROTO_IPV4     0x0800
#define IPV4_PROTO_UDP     17
#define IPV4_TTL           1

#define IPV4_OFFSET        ETH_PAYLOAD_OFFSET
#define IPV4_HDR_LEN       20
#define IPV4HDR_VER_IHL    0
#define IPV4HDR_TOS        1
#define IPV4HDR_LEN        2
#define IPV4HDR_ID         4
#define IPV4HDR_FLAGS      6
#define IPV4HDR_TTL        8
#define IPV4HDR_PROTO      9
#define IPV4HDR_CHECKSUM   10
#define IPV4HDR_SRC_IP     12
#define IPV4HDR_DST_IP     16

#define UDP_OFFSET         (IPV4_OFFSET + IPV4_HDR_LEN)
#define UDP_HDR_LEN        8
#define UDP_SRC_PORT       0
#define UDP_DST_PORT       2
#define UDP_LEN            4
#define UDP_CHECKSUM       6

#define ETHLEN             (ETH_PAYLOAD_OFFSET + MTULEN)
#define UDP_MAX_LEN        (MTULEN - IPV4_HDR_LEN)

static void
write_uint8(uint8_t *buffer, uint8_t value)
{
  buffer[0] = value;
}

static void
write_uint16(uint8_t *buffer, uint16_t value)
{
  ((uint16_t *)(buffer))[0] = value;
}

static void
write_uint32(uint8_t *buffer, uint32_t value)
{
  ((uint32_t *)(buffer))[0] = value;
}

struct mbuf *
construct_packet(struct ifnet *ifp)
{
  struct mbuf *m;
  uint8_t *eth_packet;

  if (ifp == NULL) return NULL;

  // Allocate space for the packet via the extbuf.
  m = m_get2(ETHLEN, M_WAITOK, MT_DATA, M_PKTHDR);
  if (m == NULL) return NULL;

  eth_packet = mtod(m, uint8_t *);
  if (eth_packet == NULL) return NULL;

  // Construct the packet. We're going to send a UDP packet to 224.0.0.1. From
  // here we can calculate the destination MAC for the multicast IP address.

  // DSTMAC + SRCMAC + PROTO
  eth_packet[ETH_DST_MAC_OFFSET + 0] = 0x01;
  eth_packet[ETH_DST_MAC_OFFSET + 1] = 0x00;
  eth_packet[ETH_DST_MAC_OFFSET + 2] = 0x5E;
  eth_packet[ETH_DST_MAC_OFFSET + 3] = 0x00;
  eth_packet[ETH_DST_MAC_OFFSET + 4] = 0x00;
  eth_packet[ETH_DST_MAC_OFFSET + 5] = 0x01;
  memcpy(eth_packet + ETH_SRC_MAC_OFFSET, IF_LLADDR(ifp), ETHER_ADDR_LEN);
  write_uint16(eth_packet + ETH_PROTO_OFFSET, htons(ETH_PROTO_IPV4));

  // IPv4 Header (20 bytes)
  const uint32_t srcip = 0x00000000;
  const uint32_t dstip = 0xE0000001;

  uint8_t *ipv4hdr = eth_packet + IPV4_OFFSET;
  write_uint8(ipv4hdr + IPV4HDR_VER_IHL, 0x40 | (IPV4_HDR_LEN >> 2));
  write_uint8(ipv4hdr + IPV4HDR_TOS, 0);
  write_uint16(ipv4hdr + IPV4HDR_LEN, htons(MTULEN));
  write_uint16(ipv4hdr + IPV4HDR_ID, htons(0));
  write_uint16(ipv4hdr + IPV4HDR_FLAGS, htons(0x4000));
  write_uint8(ipv4hdr + IPV4HDR_TTL, IPV4_TTL);
  write_uint8(ipv4hdr + IPV4HDR_PROTO, IPV4_PROTO_UDP);
  write_uint16(ipv4hdr + IPV4HDR_CHECKSUM, 0);   // Must be zero for cs calc
  write_uint32(ipv4hdr + IPV4HDR_SRC_IP, htonl(srcip));
  write_uint32(ipv4hdr + IPV4HDR_DST_IP, htonl(dstip));

  // UDPv4 Header (8 bytes)
  uint8_t *udphdr = eth_packet + UDP_OFFSET;
  write_uint16(udphdr + UDP_SRC_PORT, htons(3500));
  write_uint16(udphdr + UDP_DST_PORT, htons(3500));
  write_uint16(udphdr + UDP_LEN, htons(UDP_MAX_LEN));
  uint16_t udppcs = in_pseudo(srcip, dstip, UDP_MAX_LEN + IPV4_PROTO_UDP);
  write_uint16(udphdr + UDP_CHECKSUM, htons(udppcs));

  // Generate the payload of random data
  uint8_t *payload = udphdr + UDP_HDR_LEN;
  uint8_t v = 0;
  for (int p = 0; p < UDP_MAX_LEN; p++) {
    payload[p] = v;
    v++;
  }

  // Finish setting up the mbuf
  m->m_pkthdr.len = ETHLEN;
  m->m_len = ETHLEN;
  m->m_flags |= M_MCAST;

  printf("%s hwassist = %08zx\n", ifp->if_xname, ifp->if_hwassist);
  if (ifp->if_hwassist & CSUM_IP) {
    m->m_pkthdr.csum_flags |= CSUM_IP;
  } else {
    uint16_t ipcs = in_cksum_hdr((const struct ip*)(m->m_data + IPV4_OFFSET));
    if (ipcs == 0) ipcs = 0xFFFF;
    write_uint16(ipv4hdr + IPV4HDR_CHECKSUM, ipcs);
  }

  if (ifp->if_hwassist & CSUM_IP_UDP) {
    m->m_pkthdr.csum_flags |= CSUM_IP_UDP;
    m->m_pkthdr.csum_data = UDP_CHECKSUM;
  } else {
    uint16_t udpcs = in_cksum_skip(m, ETHLEN, UDP_OFFSET);
    if (udpcs == 0) udpcs = 0xFFFF;  // CS of zero not allowed.
    write_uint16(udphdr + UDP_CHECKSUM, udpcs);
  }

  return m;
}
