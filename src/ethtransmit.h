#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>

struct mbuf* construct_packet(struct ifnet *ifp);
int transmit_packet(struct ifnet *ifp);
