## This is an automatically generated record.
## The area between QNX Internal Start and QNX Internal End is controlled by
## the QNX IDE properties.
#
ifndef QCONFIG
QCONFIG=qconfig.mk
endif
include $(QCONFIG)
#
#USEFILE=
#
INSTALLDIR=/lib/dll
#
#include $(MKFILES_ROOT)/qmacros.mk
#ifndef QNX_INTERNAL
#QNX_INTERNAL=$(PROJECT_ROOT)/.qnx_internal.mk
#endif
#include $(QNX_INTERNAL)
#
#include $(MKFILES_ROOT)/qtargets.mk
#OPTIMIZE_TYPE_g=none
#OPTIMIZE_TYPE=$(OPTIMIZE_TYPE_$(filter g, $(VARIANTS)))

define PINFO
PINFO DESCRIPTION=Sample io-sock module
endef

EXTRA_CLEAN+= $(PROJECT_ROOT)/mods-showifn.use

#define MODULE_SPECIFIC_OPTIONS
#
#This can specify any module information
#
#endef

include devs/mods.mk
