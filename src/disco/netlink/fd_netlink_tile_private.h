#ifndef HEADER_fd_src_disco_netlink_fd_netlink_tile_private_h
#define HEADER_fd_src_disco_netlink_fd_netlink_tile_private_h

#include "../../waltz/ip/fd_netlink1.h"
#include "../metrics/generated/fd_metrics_netlnk.h"
#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/mib/fd_dbl_buf.h"
#include "../../waltz/mib/fd_netdev_tbl.h"
#include "../../waltz/neigh/fd_neigh4_map.h"
#include "../../waltz/neigh/fd_neigh4_probe.h"

/* FD_NETLINK_TILE_CTX_MAGIC uniquely identifies a fd_netlink_tile_ctx_t.
   CHange this whenever the fd_netlink_tile_ctx_t struct changes. */

#define FD_NETLINK_TILE_CTX_MAGIC (0xec431bf97929c691UL) /* random */

struct fd_netlink_tile_ctx {
  ulong magic; /* ==FD_NETLINK_TILE_CTX_MAGIC */

  fd_netlink_t nl_monitor[1];
  fd_netlink_t nl_req[1];

  /* Pending actions */
  ulong action;
# define FD_NET_TILE_ACTION_ROUTE4_UPDATE (1UL<<0)
# define FD_NET_TILE_ACTION_LINK_UPDATE   (1UL<<1)
# define FD_NET_TILE_ACTION_NEIGH_UPDATE  (1UL<<2)

  /* Rate limit link and route table changes (in ticks) */
  long update_backoff;
  long route4_update_ts;
  long link_update_ts;

  /* Link table */
  void *               netdev_local;  /* local mutable table */
  ulong                netdev_sz;     /* size of netdev table */
  fd_netdev_tbl_join_t netdev_tbl[1]; /* join to local mutable table */
  fd_dbl_buf_t *       netdev_buf;    /* global immutable copy */

  /* Route tables */
  fd_fib4_t * fib4_local;
  fd_fib4_t * fib4_main;

  /* Neighbor table */
  fd_neigh4_hmap_t neigh4[1];
  uint             neigh4_ifidx;
  long             idle_cnt;

  /* Allowed destination IPs hmap */
  ulong dstip_hmap_offset;
  ulong dstip_hmap_elem_offset;
  ulong dstip_cnt;
  ulong dstip_max;

  /* Neighbor table prober */
  fd_neigh4_prober_t prober[1];

  struct {
    ulong link_full_syncs;
    ulong route_full_syncs;
    ulong update_cnt[ FD_METRICS_COUNTER_NETLNK_UPDATES_CNT ];
    ulong neigh_solicits_sent;
    ulong neigh_solicits_fails;
  } metrics;
};

typedef struct fd_netlink_tile_ctx fd_netlink_tile_ctx_t;

/* Allowed destination addresses */

#define DSTIP_HMAP_LOCK_CNT (4UL)
#define DSTIP_HMAP_SEED (654321UL)

#define MAP_NAME fd_dstip_hmap
#define MAP_ELE_T fd_dstip_hmap_entry_t
#define MAP_KEY_T uint
#define MAP_KEY ip_addr
#define MAP_KEY_HASH(key,seed) fd_uint_hash( (*(key)) ^ ((uint)seed) )

struct __attribute__((aligned(16))) fd_dstip_hmap_entry {
  uint ip_addr; /* Little endian. All 32 bits defined */
  uint flags;   /* IFA_F_PERMENANT, IFA_F_NOPREFIXROUTE */
  uint scope;   /* 	RT_SCOPE_UNIVERSE, RT_SCOPE_SITE, RT_SCOPE_LINK, RT_SCOPE_HOST */
};

typedef struct fd_dstip_hmap_entry fd_dstip_hmap_entry_t;

// static inline void *  fd_dstip_hmap_mem      ( fd_fib4_t * fib ) { return (void *)( (ulong)fib + fib->hmap_offset      ); }
// static inline void *  fd_dstip_hmap_ele_mem  ( fd_fib4_t * fib ) { return (void *)( (ulong)fib + fib->hmap_elem_offset ); }

#define MAP_IMPL_STYLE 0
#include "../../util/tmpl/fd_map_slot_para.c"

#endif /* HEADER_fd_src_disco_netlink_fd_netlink_tile_private_h */
