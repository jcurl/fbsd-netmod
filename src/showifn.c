#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>

#include <net/route.h>
#include <net/ethernet.h>

#include "ethtransmit.h"

#define MODPREFIX "showifn: "

// A convenience method to print debug output in the kernel. By using
// 'mod_printf', we make it easy to update, if we ever change to a real driver,
// and then might use 'device_printf' instead.
#ifndef NDEBUG
#define mod_printf(fmt, ...)                      \
  printf(MODPREFIX fmt, ##__VA_ARGS__)
#else
#define mod_printf(fmt, ...) ((void)0)
#endif

static void
transmit(struct ifnet *ifp, struct mbuf *m)
{
  struct epoch_tracker et;

  NET_EPOCH_ENTER(et);
  // Will free the mbuf for us.
  int error = (*ifp->if_transmit)(ifp, m);
  if (error) {
    mod_printf("if_transmit returned %d\n", error);
  } else {
    mod_printf("if_transmit successful\n");
  }
  NET_EPOCH_EXIT(et);
}

static void
transmit_ro(struct ifnet *ifp, struct mbuf *m)
{
  struct epoch_tracker et;
  struct route ro;
  struct sockaddr dst;

  dst.sa_family = pseudo_AF_HDRCMPLT;
  bcopy(mtod(m, const void *), dst.sa_data, ETHER_HDR_LEN);

  m->m_pkthdr.len -= ETHER_HDR_LEN;
  m->m_len -= ETHER_HDR_LEN;
  m->m_data += ETHER_HDR_LEN;

  bzero(&ro, sizeof(ro));
  ro.ro_prepend = (u_char *)&dst.sa_data;
  ro.ro_plen = ETHER_HDR_LEN;
  ro.ro_flags = RT_HAS_HEADER;

  NET_EPOCH_ENTER(et);
  // Will free the mbuf for us.
  int error = (*ifp->if_output)(ifp, m, &dst, &ro);
  if (error) {
    mod_printf("if_output returned %d\n", error);
  } else {
    mod_printf("if_output successful\n");
  }
  NET_EPOCH_EXIT(et);
}

static void
show_ifn(void)
{
  if_t ifp = ifunit_ref("em0");
  if (ifp == NULL) ifp = ifunit_ref("genet0");
  if (ifp == NULL) {
    mod_printf("interface not found\n");
    return;
  } else {
    mod_printf("%s found\n", ifp->if_xname);
  }

  if ((ifp->if_flags & IFF_UP) == 0) {
    mod_printf("%s link down\n", ifp->if_xname);
    return;
  }

  struct mbuf *m = construct_packet(ifp);
  if (m == NULL) {
    mod_printf("%s mbuf alloc failed\n", ifp->if_xname);
    return;
  }

  transmit(ifp, m);
  if_rele(ifp);
}

static void
showifn_link_event(void *arg, struct ifnet *ifp, int linkstate)
{
  if (ifp == NULL) return;

  if (linkstate == LINK_STATE_UP) {
    mod_printf("interface %s link up\n", ifp->if_xname);
  } else if (linkstate == LINK_STATE_DOWN) {
    mod_printf("interface %s link down\n", ifp->if_xname);
  } else {
    mod_printf("interface %s has linkstate %d\n", ifp->if_xname, linkstate);
  }
}

static void
showifn_event(void *arg, struct ifnet *ifp, int event)
{
  if (ifp == NULL) return;

  if (event == IFNET_EVENT_DOWN) {
    mod_printf("interface %s down\n", ifp->if_xname);
  } else if (event == IFNET_EVENT_UP) {
    mod_printf("interface %s up\n", ifp->if_xname);
  } else {
    mod_printf("interface %s event %d\n", ifp->if_xname, event);
  }
}

static int
kmod_main(struct module *module, int event, void *arg)
{
  static eventhandler_tag link_event;
  static eventhandler_tag if_event;
  int res = 0;

  switch (event) {
    case MOD_LOAD:
      link_event = EVENTHANDLER_REGISTER(ifnet_link_event,
                                         showifn_link_event,
                                         NULL,
                                         EVENTHANDLER_PRI_ANY);
      if_event = EVENTHANDLER_REGISTER(ifnet_event,
                                       showifn_event,
                                       NULL,
                                       EVENTHANDLER_PRI_ANY);
      show_ifn();
      break;

    case MOD_UNLOAD:
      EVENTHANDLER_DEREGISTER(ifnet_link_event, link_event);
      EVENTHANDLER_DEREGISTER(ifnet_event, if_event);
      break;

    default:
      res = EOPNOTSUPP;
      break;
  }

  return res;
}

static moduledata_t
showifn_conf = {
  "showifn",
  kmod_main,
  NULL
};

DECLARE_MODULE(showifn, showifn_conf, SI_SUB_DRIVERS, SI_ORDER_ANY);
