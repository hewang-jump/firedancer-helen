#ifndef HEADER_fd_src_waltz_mib_fd_addrs_hmap_h
#define HEADER_fd_src_waltz_mib_fd_addrs_hmap_h

#include "../../util/fd_util_base.h"

/* Destination IP Filtering Structs */

struct __attribute__((aligned(16))) fd_addrs_fltr_attrs {
  uint flags; /* IFA_F_PERMENANT, IFA_F_NOPREFIXROUTE */
  uint scope; /* RT_SCOPE_UNIVERSE, RT_SCOPE_SITE, RT_SCOPE_LINK, RT_SCOPE_HOST */
};
typedef struct fd_addrs_fltr_attrs fd_addrs_fltr_attrs_t;

#define ADDRS_HMAP_LOCK_CNT (4U)
#define ADDRS_HMAP_SEED (654321UL)

#define MAP_NAME fd_addrs_hmap
#define MAP_ELE_T fd_addrs_hmap_entry_t
#define MAP_KEY_T uint
#define MAP_KEY dst_ip
#define MAP_KEY_HASH(key,seed) fd_uint_hash( (*(key)) ^ ((uint)seed) )

struct __attribute__((aligned(16))) fd_addrs_hmap_entry {
  uint dst_ip; /* Little endian. All 32 bits defined */
  fd_addrs_fltr_attrs_t fltr_attrs;
};

typedef struct fd_addrs_hmap_entry fd_addrs_hmap_entry_t;

#define MAP_IMPL_STYLE 0
#include "../../util/tmpl/fd_map_slot_para.c"

/* Attempts to find the dst_ip inside the fd_addrs_hmap. Return 1 if found and
   the fltr_attrs_out will be filled with the filter attributes associated with
   the dst_ip. Return 0 if not found.
*/
int
fd_addrs_hmap_find( fd_addrs_hmap_t * hmap,
                    uint dst_ip,
                    fd_addrs_fltr_attrs_t * fltr_attrs_out );

/* Insert a new entry (key is dst_ip, value is *fltr_attrs) into the
   fd_addrs_hmap. Assume dst_ip is not 0. Return 1 on success. 0 if map is full */
int
fd_addrs_hmap_insert( fd_addrs_hmap_t * hmap,
                 uint dst_ip,
                 fd_addrs_fltr_attrs_t * fltr_attrs );

/* Re-initialize the fd_addrs_hmap. */
void
fd_addrs_hmap_reset( fd_addrs_hmap_t * hmap,
                     void * hmap_shmem,
                     void * hmap_shmem_ele );

#endif /* HEADER_fd_src_waltz_mib_fd_addrs_hmap_h */
