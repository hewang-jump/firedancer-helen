$(call add-hdrs,fd_dbl_buf.h)
$(call add-objs,fd_dbl_buf,fd_waltz)
$(call add-hdrs,fd_netdev.h)
$(call add-objs,fd_netdev,fd_waltz)
$(call add-hdrs,fd_addrs_hmap.h)
$(call add-objs,fd_addrs_hmap,fd_waltz)
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_netdev_netlink.h)
$(call add-objs,fd_netdev_netlink,fd_waltz)
$(call make-unit-test,test_netdev_netlink,test_netdev_netlink,fd_waltz fd_util)
endif
