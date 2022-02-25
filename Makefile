include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
 
PKG_NAME:=tcp_ccp
PKG_RELEASE:=1
 
include $(INCLUDE_DIR)/package.mk
 
define KernelPackage/$(PKG_NAME)
	SUBMENU:=Other modules
	TITLE:=This is a $(PKG_NAME) driver
	FILES:=$(PKG_BUILD_DIR)/$(PKG_NAME).ko
	AUTOLOAD:=$(call AutoLoad,30,,1)
	KCONFIG:=
endef
 
define KernelPackage/$(PKG_NAME)/description
	This is a $(PKG_NAME) device.
endef
 
EXTRA_KCONFIG:= \
		CONFIG_TCP_CCP=m
 
EXTRA_CFLAGS:= \
		$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
		$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \
 
MAKE_OPTS:= \
		ARCH="$(LINUX_KARCH)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		SUBDIRS="$(PKG_BUILD_DIR)/" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		$(EXTRA_KCONFIG)
 
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
 
define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef
 
$(eval $(call KernelPackage,$(PKG_NAME)))
