#ifndef HEADER_fd_src_waltz_mib_fd_netdev_h
#define HEADER_fd_src_waltz_mib_fd_netdev_h

/* fd_netdev.h provides a network interface table */

#include "../../util/fd_util_base.h"
#include "fd_addrs_hmap.h"

/* FD_OPER_STATUS_* give the operational state of a network interface.
   See RFC 2863 Section 3.1.14: https://datatracker.ietf.org/doc/html/rfc2863#section-3.1.14 */

#define FD_OPER_STATUS_INVALID          (0)
#define FD_OPER_STATUS_UP               (1)  /* ready to pass packets */
#define FD_OPER_STATUS_DOWN             (2)
#define FD_OPER_STATUS_TESTING          (3) /* in some test mode */
#define FD_OPER_STATUS_UNKNOWN          (4) /* status can not be determined */
#define FD_OPER_STATUS_DORMANT          (5)
#define FD_OPER_STATUS_NOT_PRESENT      (6) /* some component is missing */
#define FD_OPER_STATUS_LOWER_LAYER_DOWN (7) /* down due to state of lower-layer interface(s) */

/* fd_netdev_entry_t holds basic configuration of a network device. */

struct fd_netdev_entry {
  ushort mtu;            /* Largest layer-3 payload that fits in a packet */
  uchar  mac_addr[6];    /* MAC address */
  ushort if_idx;         /* Interface index */
  short  slave_tbl_idx;  /* index to bond slave table, -1 if not a bond master */
  short  master_idx;     /* index of bond master, -1 if not a bond slave */
  char   name[16];       /* cstr interface name (max 15 length) */
  uchar  oper_status;    /* one of FD_OPER_STATUS_{...} */
  ushort dev_type;       /* one of ARPHRD_ETHER/_LOOPBACK_/IPGRE*/
  uint   gre_dst_ip;
  uint   gre_src_ip;
};

typedef struct fd_netdev_entry fd_netdev_entry_t;

/* FD_NETDEV_BOND_SLAVE_MAX is the max supported number of bond slaves. */

#define FD_NETDEV_BOND_SLAVE_MAX (16)

/* fd_netdev_bond_t lists active slaves of a bond device. */

struct fd_netdev_bond {
  uchar  slave_cnt;
  ushort slave_idx[ FD_NETDEV_BOND_SLAVE_MAX ];
};

typedef struct fd_netdev_bond fd_netdev_bond_t;

/* fd_netdev_obj_t provides an interface table and an address hashmap.

   The interface table is optimized for frequent reads and rare writes. It is
   generally not thread-safe to modify the table in-place.  The only safe
   way to sync modifications to other threads is by copying the table in
   its entirety.

   The address hashmap is also optimized for frequent reads and rare writes.
   Writes to the hashmap are blocking, during which read will fail. Therefore
   it's safe to modify the hashmap in-place, but reads should always be checked
   for failure.
   */

struct fd_netdev_obj_private;
typedef struct fd_netdev_obj_private fd_netdev_obj_t;

struct fd_netdev_obj_hdr {
  ushort dev_max;
  ushort bond_max;
  ushort dev_cnt;
  ushort bond_cnt;
  void * addrs_mem;
  void * addrs_ele_mem;
  ulong  addrs_max;
  ulong  addrs_cnt;
};
typedef struct fd_netdev_obj_hdr fd_netdev_obj_hdr_t;

struct fd_netdev_obj_join {
  fd_netdev_obj_hdr_t * hdr;
  fd_netdev_entry_t   * dev_tbl;
  fd_netdev_bond_t    * bond_tbl;
  fd_addrs_hmap_t       addrs_hmap[1];  // join handle to fd_addrs_hmap
};
typedef struct fd_netdev_obj_join fd_netdev_obj_join_t;

#define FD_NETDEV_TBL_MAGIC (0xd5f9ba2710d6bf0aUL) /* random */

/* FD_NETDEV_TBL_ALIGN is the return value of fd_netdev_tbl_align() */

#define FD_NETDEV_TBL_ALIGN (16UL)

FD_PROTOTYPES_BEGIN

/* fd_netdev_tbl_{align,footprint} describe a memory region suitable to
   back a netdev_tbl with dev_max interfaces and bond_max bond masters. */

FD_FN_CONST ulong
fd_netdev_tbl_align( void );

FD_FN_CONST ulong
fd_netdev_tbl_footprint( ulong dev_max,
                         ulong bond_max );

/* fd_netdev_new formats a memory region as an empty netdev object, creates an
   empty netdev table as part of the memory, and stores pointers to the address
   hashmap. Assume the address hmap's shhmap and shhmap_ele have been properly
   initialized by calling hmap_new(). Returns shmem on success. On failure
   returns NULL and logs reason for failure. */

void *
fd_netdev_new( void * shmem,
               void * shhmap,
               void * shhmap_ele,
               ulong  dev_max,
               ulong  bond_max,
               ulong  hmap_max );

/* fd_netdev_join joins a netdev_obj at shmem. Assume shmem has been properly
   initialized by calling fd_netdev_new. ljoin points to a
   fd_netdev_obj_join_t[1] to which object information is written to. Returns
   ljoin on success. On failure, returns NULL and logs reason for failure. */

fd_netdev_obj_join_t *
fd_netdev_join( void * ljoin,
                void * shmem );

/* fd_netdev_leave undoes a fd_netdev_join.  Returns ownership
   of the region backing join to the caller.  (Warning: This returns ljoin,
   not shmem) */

void *
fd_netdev_leave( fd_netdev_obj_join_t * join );

/* fd_netdev_delete unformats the memory region backing a netdev object
   and returns ownership of the region back to the caller. */

void *
fd_netdev_delete( void * shmem );

/* fd_netdev_tbl_reset resets the table to the state of a newly constructed
   empty object (clears all devices and bonds). Does not modify the netdev
   address hashmap. */

void
fd_netdev_tbl_reset( fd_netdev_obj_join_t * join );

/* fd_netdev_hmap_reset resets the address hmap inside the netdev object to
   the state of a newly constructed empty object (clears all inserted entries).
   This operation is blocking. Does not modify the netdev table */

void
fd_netdev_hmap_reset( fd_netdev_obj_join_t * join );

#if FD_HAS_HOSTED

/* fd_netdev_tbl_fprintf prints the interface table to the given FILE *
   pointer (or target equivalent).  Outputs ASCII encoding with LF
   newlines.  Returns errno on failure and 0 on success. */

int
fd_netdev_tbl_fprintf( fd_netdev_obj_join_t const * tbl,
                       void *                       file );

#endif /* FD_HAS_HOSTED */

FD_PROTOTYPES_END

char const *
fd_oper_status_cstr( uint oper_status );

#endif /* HEADER_fd_src_waltz_mib_fd_netdev_h */
