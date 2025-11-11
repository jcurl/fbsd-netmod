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

#include <sys/sysctl.h>
#include <qnx/qnx_modload.h>

#include "ethtransmit.h"

int mod_ver = IOSOCK_VERSION_CUR;

SYSCTL_INT(_qnx_module, OID_AUTO, sample, CTLFLAG_RD, &mod_ver, 0,
            "Version");


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
#if __FreeBSD_version < 1403000
  int error = ifp->if_transmit(ifp, m);
#else
  // Defined in ifnet(9) FreeBSD 14.3 and later.
  int error = if_transmit(ifp, m);
#endif
  if (error) {
    mod_printf("if_transmit returned %d\n", error);
  } else {
    mod_printf("if_transmit successful\n");
  }
  NET_EPOCH_EXIT(et);
}

static void
show_ifn(void)
{
  if_t ifp = ifunit_ref("em0");
  if (ifp == NULL) ifp = ifunit_ref("genet0");
  if (ifp == NULL) ifp = ifunit_ref("eth0");
  if (ifp == NULL) {
    mod_printf("interface not found\n");
    return;
  } else {
    mod_printf("%s found\n", if_name(ifp));
  }

  if ((if_getflags(ifp) & IFF_UP) == 0) {
    mod_printf("%s link down\n", if_name(ifp));
    return;
  }

  struct mbuf *m = construct_packet(ifp);
  if (m == NULL) {
    mod_printf("%s mbuf alloc failed\n", if_name(ifp));
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
    mod_printf("interface %s link up\n", if_name(ifp));
  } else if (linkstate == LINK_STATE_DOWN) {
    mod_printf("interface %s link down\n", if_name(ifp));
  } else {
    mod_printf("interface %s has linkstate %d\n", if_name(ifp), linkstate);
  }
}

static void
showifn_event(void *arg, struct ifnet *ifp, int event)
{
  if (ifp == NULL) return;

  if (event == IFNET_EVENT_DOWN) {
    mod_printf("interface %s down\n", if_name(ifp));
  } else if (event == IFNET_EVENT_UP) {
    mod_printf("interface %s up\n", if_name(ifp));
  } else {
    mod_printf("interface %s event %d\n", if_name(ifp), event);
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

MODULE_VERSION(showifn, 1);
DECLARE_MODULE(showifn, showifn_conf, SI_SUB_DRIVERS, SI_ORDER_ANY);

struct _iosock_module_version iosock_module_version =
    IOSOCK_MODULE_VER_SYM_INIT;

static void
kmod_uninit(void *arg)
{
}
/*
 * If code is added to sam_uninit, then SI_SUB_DUMMY needs to be
 * changed to SI_SUB_DRIVERS.  With SI_SUB_DUMMY, sam_uninit does
 * not get called.
 */
SYSUNINIT(kmod_uninit, SI_SUB_DUMMY, SI_ORDER_ANY, kmod_uninit, NULL);
