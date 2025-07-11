#ifndef HEADER_fd_src_waltz_ip_fd_ipfilter_h
#define HEADER_fd_src_waltz_ip_fd_ipfilter_h

#include "../../util/fd_util_base.h"
#include "fd_netlink1.h"

struct __attribute__((aligned(16))) fd_ipfilter {
  uint flags; /* IFA_F_PERMENANT, IFA_F_NOPREFIXROUTE */
  uint scope; /* RT_SCOPE_UNIVERSE, RT_SCOPE_SITE, RT_SCOPE_LINK, RT_SCOPE_HOST */
};
typedef struct fd_ipfilter fd_ipfilter_t;

/* Destination IP Filtering */

#define IPFILTER_HMAP_MAX (8192U)
#define IPFILTER_HMAP_LOCK_CNT (4U)
#define IPFILTER_HMAP_SEED (654321UL)

#define MAP_NAME fd_ipfilter_hmap
#define MAP_ELE_T fd_ipfilter_hmap_entry_t
#define MAP_KEY_T uint
#define MAP_KEY ip_addr
#define MAP_KEY_HASH(key,seed) fd_uint_hash( (*(key)) ^ ((uint)seed) )

struct __attribute__((aligned(16))) fd_ipfilter_hmap_entry {
  uint ip_addr; /* Little endian. All 32 bits defined */
  fd_ipfilter_t filter;
};

typedef struct fd_ipfilter_hmap_entry fd_ipfilter_hmap_entry_t;

// static inline void *  fd_dstip_hmap_mem      ( fd_fib4_t * fib ) { return (void *)( (ulong)fib + fib->hmap_offset      ); }
// static inline void *  fd_dstip_hmap_ele_mem  ( fd_fib4_t * fib ) { return (void *)( (ulong)fib + fib->hmap_elem_offset ); }

#define MAP_IMPL_STYLE 0
#include "../../util/tmpl/fd_map_slot_para.c"


int
fd_netlink_get_all_ips( fd_netlink_t * netlink,
                        fd_ipfilter_hmap_t * hmap );

int
fd_netlink_ipfilter_query( fd_ipfilter_hmap_t * hmap,
                           uint ipaddr,
                           fd_ipfilter_t * filter );


#endif /* HEADER_fd_src_waltz_ip_fd_dstfilter_h */
