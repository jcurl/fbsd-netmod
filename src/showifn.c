#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>

static void show_ifn(void)
{
  struct ifnet *ifp;

  IFNET_RLOCK();
  CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link) {
    printf(" %s via %s\n", ifp->if_xname, ifp->if_dname);
  }
  IFNET_RUNLOCK();
}

static int kmod_main(struct module *module, int event, void *arg)
{
  int res = 0;

  switch (event) {
    case MOD_LOAD:
      printf("showifn loading\n");
      show_ifn();
      break;

    case MOD_UNLOAD:
      printf("showifn unloading\n");
      break;

    default:
      res = EOPNOTSUPP;
      break;
  }

  return res;
}

static moduledata_t showifn_conf = {
  "showifn",
  kmod_main,
  NULL
};

DECLARE_MODULE(showifn, showifn_conf, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
