#
# tools/xl/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 1.0
MINOR = 1

CFLAGS += -Werror -Wno-format-zero-length -Wmissing-declarations \
	-Wno-declaration-after-statement -Wformat-nonliteral
CFLAGS += -I. -fPIC

CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)

CFLAGS_XL += $(CFLAGS_libxenlight)
CFLAGS_XL += -Wshadow

XL_OBJS-$(CONFIG_X86) = xl_psr.o
XL_OBJS = xl.o xl_cmdtable.o xl_sxp.o xl_utils.o $(XL_OBJS-y)
XL_OBJS += xl_parse.o xl_cpupool.o xl_flask.o
XL_OBJS += xl_vtpm.o xl_block.o xl_nic.o xl_usb.o
XL_OBJS += xl_sched.o xl_pci.o xl_vcpu.o xl_cdrom.o xl_mem.o
XL_OBJS += xl_info.o xl_console.o xl_misc.o
XL_OBJS += xl_vmcontrol.o xl_saverestore.o xl_migrate.o
XL_OBJS += xl_vdispl.o xl_vsnd.o xl_vkb.o

$(XL_OBJS): CFLAGS += $(CFLAGS_libxentoollog)
$(XL_OBJS): CFLAGS += $(CFLAGS_XL)
$(XL_OBJS): CFLAGS += -include $(XEN_ROOT)/tools/config.h # libxl_json.h needs it.

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))

$(XL_OBJS): _paths.h

ALL_TARGETS = xl libxl.a libxl.so

.PHONY: all
all: $(ALL_TARGETS)

xl: $(XL_OBJS) libxl.so libxl.a
	$(CC) $(LDFLAGS) -o $@ $(XL_OBJS) $(LDLIBS_libxlutil) $(LDLIBS_libxenlight) $(LDLIBS_libxentoollog) -lyajl $(APPEND_LDFLAGS)

libxl.a: $(XL_OBJS)
	$(AR) rcs $@ $^

libxl.so.$(MAJOR).$(MINOR): APPEND_LDFLAGS += -ldl

libxl.so: libxl.so.$(MAJOR)
	ln -sf $< $@

libxl.so.$(MAJOR): libxl.so.$(MAJOR).$(MINOR)
	ln -sf $< $@
libxl.so.$(MAJOR).$(MINOR): xl_saverestore.opic xl_parse.opic xl_utils.opic xl.opic xl_block.opic xl_cdrom.opic xl_cmdtable.opic xl_console.opic xl_cpupool.opic xl_flask.opic xl_mem.opic xl_migrate.opic xl_nic.opic xl_pci.opic xl_psr.opic xl_sched.opic xl_sxp.opic xl_usb.opic xl_vcpu.opic xl_vdispl.opic xl_vkb.opic xl_vmcontrol.opic xl_vsnd.opic xl_vtpm.opic xl_misc.opic
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxl.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LDLIBS_libxentoolcore) $(SOCKET_LIBS) $(PTHREAD_LIBS) -lyajl $(APPEND_LDFLAGS)



.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(BASH_COMPLETION_DIR)
	$(INSTALL_PROG) xl $(DESTDIR)$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_SHLIB) libxl.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	ln -sf libxl.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxl.so.$(MAJOR)
	ln -sf libxl.so.$(MAJOR) $(DESTDIR)$(libdir)/libxl.so
	$(INSTALL_DATA) libxl.a $(DESTDIR)$(libdir)
	$(INSTALL_DATA) bash-completion $(DESTDIR)$(BASH_COMPLETION_DIR)/xl.sh

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(BASH_COMPLETION_DIR)/xl.sh
	rm -f $(DESTDIR)$(sbindir)/xl
	rm -f $(DESTDIR)$(libdir)/libxl.a
	rm -f $(DESTDIR)$(libdir)/libxl.so
	rm -f $(DESTDIR)$(libdir)/libxl.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxl.so.$(MAJOR).$(MINOR)

.PHONY: clean
clean:
	$(RM) -f *.o xl _paths.h $(DEPS_RM)
	$(RM) -f *.a *.o *.opic *.so* xl _paths.h $(DEPS_RM)

distclean: clean


-include $(DEPS_INCLUDE)
