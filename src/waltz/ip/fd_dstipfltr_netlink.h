#ifndef HEADER_fd_src_waltz_ip_fd_dstipfltr_h
#define HEADER_fd_src_waltz_ip_fd_dstipfltr_h

#include "../../util/fd_util_base.h"
#include "fd_netlink1.h"

/* Destination IP Filtering Structs */

struct __attribute__((aligned(16))) fd_dstipfltr_params {
  uint flags; /* IFA_F_PERMENANT, IFA_F_NOPREFIXROUTE */
  uint scope; /* RT_SCOPE_UNIVERSE, RT_SCOPE_SITE, RT_SCOPE_LINK, RT_SCOPE_HOST */
};
typedef struct fd_dstipfltr_params fd_dstipfltr_params_t;

#define DSTIPFLTR_HMAP_MAX (8192U)
#define DSTIPFLTR_HMAP_LOCK_CNT (4U)
#define DSTIPFLTR_HMAP_SEED (654321UL)

#define MAP_NAME fd_dstipfltr_hmap
#define MAP_ELE_T fd_dstipfltr_hmap_entry_t
#define MAP_KEY_T uint
#define MAP_KEY dst_ip
#define MAP_KEY_HASH(key,seed) fd_uint_hash( (*(key)) ^ ((uint)seed) )

struct __attribute__((aligned(16))) fd_dstipfltr_hmap_entry {
  uint dst_ip; /* Little endian. All 32 bits defined */
  fd_dstipfltr_params_t fltr_params;
};

typedef struct fd_dstipfltr_hmap_entry fd_dstipfltr_hmap_entry_t;

#define MAP_IMPL_STYLE 0
#include "../../util/tmpl/fd_map_slot_para.c"

/* Destination IP Filtering API */

/* Create a dstipfltr join handle to the shmem. Return hmap on success, NULL
  on failure. */
void *
fd_netlink_dstipfltr_join( fd_dstipfltr_hmap_t * hmap,
                           void * shmem );

/* Load the dstipfltr hmap from kernel */
int
fd_netlink_dstipfltr_load( fd_netlink_t * netlink,
                           fd_dstipfltr_hmap_t * hmap );

/* Check the destination ip is allowed. Return 1 if allowed. 0 if not allowed */
int
fd_netlink_dstipfltr_check( fd_dstipfltr_hmap_t * hmap,
                            uint dst_ip,
                            fd_dstipfltr_params_t * ipfltr_params_out );

#endif /* HEADER_fd_src_waltz_ip_fd_dstipfltr_h */
