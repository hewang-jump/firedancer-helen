#include "fd_microblock.h"
#define FD_TILE_TEST
#define _GNU_SOURCE

#include <errno.h>    /* errno */
#include <sys/mman.h> /* MAP_FAILED, memfd_create */

// #include <unistd.h> /* getgid, getuid, setegid, seteuid */
// #include <sys/stat.h> /* stat */
// #include <dirent.h> /* DIR */

#include "../../app/platform/fd_file_util.h"
#include "../../app/shared/fd_config.h"
#include "../../app/shared/fd_obj_callbacks.c"
#include "../../app/shared/fd_action.h"
#include "../../util/fd_util_base.h"

/* Frankendancer topology */
#include "../../app/fdctl/topology.c"

extern fd_topo_obj_callbacks_t fd_obj_cb_mcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_dcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_fseq;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_opaque;
extern fd_topo_obj_callbacks_t fd_obj_cb_dbl_buf;
extern fd_topo_obj_callbacks_t fd_obj_cb_neigh4_hmap;
extern fd_topo_obj_callbacks_t fd_obj_cb_fib4;
extern fd_topo_obj_callbacks_t fd_obj_cb_keyswitch;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
  &fd_obj_cb_mcache,
  &fd_obj_cb_dcache,
  &fd_obj_cb_fseq,
  &fd_obj_cb_metrics,
  &fd_obj_cb_opaque,
  &fd_obj_cb_dbl_buf,
  &fd_obj_cb_neigh4_hmap,
  &fd_obj_cb_fib4,
  &fd_obj_cb_keyswitch,
  &fd_obj_cb_tile,
  NULL,
};

/* Tile under test */
extern fd_topo_run_tile_t fd_tile_pack;

/* Dummy tiles to fill up the topology - Frankendancer. */
fd_topo_run_tile_t dummy_tile_net    = { .name = "net" };
fd_topo_run_tile_t dummy_tile_netlnk = { .name = "netlnk" };
fd_topo_run_tile_t dummy_tile_sock   = { .name = "sock" };
fd_topo_run_tile_t dummy_tile_quic   = { .name = "quic" };
fd_topo_run_tile_t dummy_tile_bundle = { .name = "bundle" };
fd_topo_run_tile_t dummy_tile_verify = { .name = "verify" };
fd_topo_run_tile_t dummy_tile_dedup  = { .name = "dedup" };
// fd_topo_run_tile_t dummy_tile_pack   = { .name = "pack" };   /* replaced by fd_tile_pack */
fd_topo_run_tile_t dummy_tile_shred  = { .name = "shred" };
fd_topo_run_tile_t dummy_tile_sign   = { .name = "sign" };
fd_topo_run_tile_t dummy_tile_metric = { .name = "metric" };
fd_topo_run_tile_t dummy_tile_cswtch = { .name = "cswtch" };
fd_topo_run_tile_t dummy_tile_gui    = { .name = "gui" };
fd_topo_run_tile_t dummy_tile_plugin = { .name = "plugin" };
fd_topo_run_tile_t dummy_tile_bencho = { .name = "bencho" };
fd_topo_run_tile_t dummy_tile_benchg = { .name = "benchg" };
fd_topo_run_tile_t dummy_tile_benchs = { .name = "benchs" };
fd_topo_run_tile_t dummy_tile_pktgen = { .name = "pktgen" };
fd_topo_run_tile_t dummy_tile_resolv = { .name = "resolv" };
fd_topo_run_tile_t dummy_tile_poh    = { .name = "poh" };
fd_topo_run_tile_t dummy_tile_bank   = { .name = "bank" };
fd_topo_run_tile_t dummy_tile_store  = { .name = "store" };


fd_topo_run_tile_t * TILES[] = {
  &dummy_tile_net,
  &dummy_tile_netlnk,
  &dummy_tile_sock,
  &dummy_tile_quic,
  &dummy_tile_bundle,
  &dummy_tile_verify,
  &dummy_tile_dedup,
//   &dummy_tile_pack,  /* replaced by fd_tile_pack */
  &dummy_tile_shred,
  &dummy_tile_sign,
  &dummy_tile_metric,
  &dummy_tile_cswtch,
  &dummy_tile_gui,
  &dummy_tile_plugin,
  &dummy_tile_bencho,
  &dummy_tile_benchg,
  &dummy_tile_benchs,
  &dummy_tile_pktgen,
  &dummy_tile_resolv,
  &dummy_tile_poh,
  &dummy_tile_bank,
  &dummy_tile_store,
  &fd_tile_pack,
  NULL,
};

action_t * ACTIONS[] = {
  NULL,
};

#include <unistd.h>

#include "fd_pack_tile.c"
#include "fd_pack.c"
#include "fd_pack_cost.h"
const char SIGNATURE_SUFFIX[ FD_TXN_SIGNATURE_SZ - sizeof(ulong) - sizeof(uint) ] = ": this is the fake signature of transaction number ";
const char WORK_PROGRAM_ID[ FD_TXN_ACCT_ADDR_SZ ] = "Work Program Id Consumes 1<<j CU";
const char COMMISSION_PUBKEY[ 32 ] = { 1,2,3,4,5,6,7,8,9,10,
                                      11,12,13,14,15,16,17,18,
                                      19,20,21,22,23,24,25,26,
                                      27,28,29,30,31,32 };
const char COMMISSION              = 2;
static ulong signer                = 0;
#define MAX_TEST_TXNS (26)
static fd_txn_p_t txn_scratch[ MAX_TEST_TXNS ] = {0};
static ulong      txnp_sz[ MAX_TEST_TXNS     ] = {0};
static ulong      txnt_sz[ MAX_TEST_TXNS     ] = {0};
static uchar      metrics_scratch[ FD_METRICS_FOOTPRINT( 10, 10 ) ] __attribute__((aligned(FD_METRICS_ALIGN))) = {0};

static const char *
accs [ MAX_TEST_TXNS ] = {
  "A",
  "B",
  "C",
  "D",
  "E",
  "F",
  "G",
  "H",
  "I",
  "J",
  "K",
  "L",
  "M",
  "N",
  "O",
  "P",
  "Q",
  "R",
  "S",
  "T",
  "U",
  "V",
  "W",
  "X",
  "Y",
  "Z"
};

#define MAX_PRIORITY (13.5)
#define TICKS_PER_SLOT (64)
#define TICK_DURATION_NS (6400)
#define SLOT_DURATION_NS (TICKS_PER_SLOT * TICK_DURATION_NS)
#define MAX_MICROBLOCKS_PER_SLOT (32768UL)

static ulong epoch = 0;


config_t config[1];

/* From test_pack.c
   Makes enough of a transaction to schedule that reads one account for
   each character in reads and writes one account for each character in
   writes.  The characters before the nul-terminator in reads and writes
   should be in [0x30, 0x70), basically numbers and uppercase letters.
   Adds a unique signer.  A computeBudgetInstruction will be included
   with compute requested cus and another instruction will be added
   requesting loaded_data_sz bytes of accounts data.  Fee will be set to
   5^priority, so that even with a large stall, it should still schedule
   in decreasing priority order.  priority should be in (0, 13.5].
   Stores the created transaction in txn_scratch[ i ] and
   payload_scratch[ i ]. Return the priority fee*/
static ulong
make_transaction1( fd_txn_p_t * txnp,
                   ulong        i,
                   uint         compute,
                   uint         loaded_data_sz,
                   double       priority,
                   char const * writes,
                   char const * reads ) {
  uchar * p = txnp->payload;
  uchar * p_base = p;
  fd_txn_t * t = TXN( txnp );

  *(p++) = (uchar)1;
  fd_memcpy( p,                                   &i,               sizeof(ulong)                                    );
  fd_memcpy( p+sizeof(ulong),                     SIGNATURE_SUFFIX, FD_TXN_SIGNATURE_SZ - sizeof(ulong)-sizeof(uint) );
  fd_memcpy( p+FD_TXN_SIGNATURE_SZ-sizeof(ulong), &compute,         sizeof(uint)                                     );
  p                         += FD_TXN_SIGNATURE_SZ;
  t->transaction_version    = FD_TXN_VLEGACY;
  t->signature_cnt          = 1;
  t->signature_off          = 1;
  t->message_off            = FD_TXN_SIGNATURE_SZ+1UL;
  t->readonly_signed_cnt    = 0;
  ulong programs_to_include = 2UL; /* 1 for compute budget, 1 for "work" program */
  t->readonly_unsigned_cnt  = (uchar)(strlen( reads ) + programs_to_include);
  t->acct_addr_cnt          = (ushort)(1UL + strlen( reads ) + programs_to_include + strlen( writes ));
  t->acct_addr_off          = FD_TXN_SIGNATURE_SZ+1UL;

  /* Add the signer */
  *p = 's'; fd_memcpy( p+1, &signer, sizeof(ulong) ); memset( p+9, 'S', FD_TXN_ACCT_ADDR_SZ-9 ); p += FD_TXN_ACCT_ADDR_SZ;
  /* Add the writable accounts */
  for( ulong i = 0UL; writes[i] != '\0'; i++ ) {
    memset( p, writes[i], FD_TXN_ACCT_ADDR_SZ );
    p += FD_TXN_ACCT_ADDR_SZ;
  }
  /* Add the compute budget */
  fd_memcpy( p, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ); p += FD_TXN_ACCT_ADDR_SZ;
  /* Add the work program */
  fd_memcpy( p, WORK_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ); p += FD_TXN_ACCT_ADDR_SZ;
  /* Add the readonly accounts */
  for( ulong i = 0UL; reads[i] != '\0'; i++ ) {
    memset( p, reads[i], FD_TXN_ACCT_ADDR_SZ );
    p += FD_TXN_ACCT_ADDR_SZ;
  }

  t->recent_blockhash_off         = 0;
  t->addr_table_lookup_cnt        = 0;
  t->addr_table_adtl_writable_cnt = 0;
  t->addr_table_adtl_cnt          = 0;
  t->instr_cnt                    = 3U;
  uchar prog_start                = (uchar)(1UL+strlen( writes ));

  t->instr[ 0 ].program_id = prog_start;
  t->instr[ 0 ].acct_cnt   = 0;
  t->instr[ 0 ].data_sz    = 5;    // "2" and then "compute"
  t->instr[ 0 ].acct_off   = (ushort)(p - p_base);
  t->instr[ 0 ].data_off   = (ushort)(p - p_base);

  /* Write instruction data */
  *p = 2; fd_memcpy( p+1, &compute, sizeof(uint) );
  p += 5UL;

  t->instr[ 1 ].program_id = prog_start;
  t->instr[ 1 ].acct_cnt   = 0;
  t->instr[ 1 ].data_sz    = 9;     // "3" and then "rewards_per_cu"
  t->instr[ 1 ].acct_off   = (ushort)(p - p_base);
  t->instr[ 1 ].data_off   = (ushort)(p - p_base);

  /* 3 corresponds to SetComputeUnitPrice */
  ulong rewards_per_cu = (ulong) (pow( 5.0, priority )*10000.0 / (double)compute);
  *p = 3; fd_memcpy( p+1, &rewards_per_cu, sizeof(ulong) );
  p += 9UL;

  t->instr[ 2 ].program_id = prog_start;
  t->instr[ 2 ].acct_cnt   = 0;
  t->instr[ 2 ].data_sz    = 5;     // "4" and then "loaded_data_sz"
  t->instr[ 2 ].acct_off   = (ushort)(p - p_base);
  t->instr[ 2 ].data_off   = (ushort)(p - p_base);

  /* 4 corresponds to SetLoadedAccountsDataSizeLimit */
  *p = 4; fd_memcpy( p+1, &loaded_data_sz, sizeof(uint) );
  p  += 5UL;

  txnp->payload_sz = (ulong)(p-p_base);
  uint flags;
  ulong opt_fee;
  ulong cost = fd_pack_compute_cost( TXN( txnp ), txnp->payload, &flags, NULL, &opt_fee, NULL, NULL);
  FD_TEST( cost );

  return opt_fee;
}

/* From test_pack.c: call make_txn1(...).
   Txn_i has priority strictly greater Txn_j if i<j.
*/
static ulong
make_transaction( fd_txn_p_t * txnp,
                  ulong        i,
                  const char * w_accs,
                  const char * r_accs ) {
  double priority     = MAX_PRIORITY - (double)i*0.2;
  FD_TEST( priority>0 );
  ulong  priority_fee = make_transaction1( txnp, i, 500U, 500U, priority, w_accs, r_accs );
  FD_LOG_NOTICE(( "make_transaction_%lu, priority: %lf, reward: %lu", i, priority, priority_fee ));
  ++signer;
  return priority_fee;
}

/* make a bundle with 'bundle_txn_cnt' number of txnes starting at
   'bundle_txn_i_start' in the txn_scratch. */
static void
make_bundle( int bundle_txn_cnt,
             int bundle_txn_i_start ) {

  FD_TEST( (ulong)bundle_txn_cnt<=FD_PACK_MAX_TXN_PER_BUNDLE );
  FD_TEST( 0<=bundle_txn_i_start && bundle_txn_i_start+bundle_txn_cnt <= MAX_TEST_TXNS );

  fd_txn_p_t * txnp = txn_scratch + bundle_txn_i_start;

  const char empty_w_acc[1] = {0};
  for( int i=bundle_txn_i_start; i<bundle_txn_i_start+bundle_txn_cnt; i++ ) {
    make_transaction( txnp, (ulong)i, empty_w_acc, accs[i] );
    FD_TEST( txnp->payload_sz );
    txnp++;
  }
}


static void
make_leader( fd_became_leader_t * leader ) {
  FD_TEST( leader );
  FD_LOG_NOTICE(( "make_leader" ));
  *leader = (fd_became_leader_t) {
    .slot_start_ns           = fd_log_wallclock(),
    .slot_end_ns             = fd_log_wallclock() + SLOT_DURATION_NS,
    .max_microblocks_in_slot = MAX_MICROBLOCKS_PER_SLOT,
    .ticks_per_slot          = TICKS_PER_SLOT,
    .epoch                   = epoch,
    .limits                  = { FD_PACK_MAX_COST_PER_BLOCK_LOWER_BOUND,
                                 FD_PACK_MAX_VOTE_COST_PER_BLOCK_LOWER_BOUND,
                                 FD_PACK_MAX_WRITE_COST_PER_ACCT_LOWER_BOUND }
  };
}

/* Print the treap with all txns inserted */
void FD_FN_UNUSED
print_insert( fd_pack_ctx_t * pack_ctx ) {
  char empty_w_acc[1] = {0};
  ulong delete_cnt;
  ulong prev_reward = ULONG_MAX;

  for( int i=0; i<MAX_TEST_TXNS; i++ ) {
    FD_LOG_NOTICE(( "R acc: %s", accs[ i ] ));

    fd_txn_e_t * cur_spot = fd_pack_insert_txn_init( pack_ctx->pack );
    ulong curr_reward = make_transaction( &txn_scratch[i], (ulong)i, empty_w_acc, accs[ i ] );
    FD_TEST( curr_reward < prev_reward );
    prev_reward = curr_reward;

    fd_txn_p_t * txnp     = &txn_scratch[i];
    fd_txn_t   * txn      = TXN( txnp );
    txnp_sz[i]        = sizeof(fd_txn_p_t);
    txnt_sz[i]        = (ushort) fd_txn_footprint( txn->instr_cnt, txn->addr_table_adtl_cnt );
    fd_memcpy( cur_spot->txnp->payload, txnp, txnp_sz[i] );
    fd_memcpy( TXN(cur_spot->txnp),     txn,  txnt_sz[i] );
    fd_pack_insert_txn_fini( pack_ctx->pack, cur_spot, 0, &delete_cnt );
  }

  treap_t * txn_treap       = &pack_ctx->pack->pending[0];
  fd_pack_ord_txn_t  * pool = pack_ctx->pack->pool;
  treap_rev_iter_t prev     = treap_idx_null();
  for( treap_rev_iter_t _cur = treap_rev_iter_init( txn_treap, pool ); !treap_rev_iter_done( _cur ); _cur=prev ) {
    /* Capture next so that we can delete while we iterate. */
    prev = treap_rev_iter_next( _cur, pool );
    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );
    FD_LOG_HEXDUMP_NOTICE(( "txn payload in treap", cur->txn->payload+0xa0, 8 ));   // print the read accounts
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  char const * user_config_path = fd_env_strip_cmdline_cstr ( &argc, &argv, "--config",    NULL,            NULL );
  uint         rng_seed         = fd_env_strip_cmdline_uint ( &argc, &argv, "--rng-seed",  NULL,              0U );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, 0UL ) );

  int is_firedancer       = 0;
  int is_local_cluster    = 0;
  int netns = fd_env_strip_cmdline_contains( &argc, &argv, "--netns" );
  FD_IMPORT_BINARY( default_config, "src/app/fdctl/config/default.toml" );

  char * user_config = NULL;
  ulong user_config_sz = 0UL;
  if( FD_LIKELY( user_config_path ) ) {
    user_config = fd_file_util_read_all( user_config_path, &user_config_sz );
    if( FD_UNLIKELY( user_config==MAP_FAILED ) ) FD_LOG_ERR(( "failed to read user config file `%s` (%d-%s)", user_config_path, errno, fd_io_strerror( errno ) ));
  }
  fd_memset( config, 0, sizeof( config_t ) );
  fd_config_load( is_firedancer, netns, is_local_cluster, (const char *)default_config, default_config_sz, user_config, user_config_sz, user_config_path, config );
  fd_topo_initialize( config );

  /* ........................... */
  /* TODO remove? */
  // fd_shmem_private_boot( &argc, &argv );
  // fd_tile_private_boot( 0, NULL );
  /* ........................... */

  for( ulong i=0UL; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];
    // FD_LOG_NOTICE(( "Creating workspace %s (--page-cnt %lu, --page-sz %lu, --cpu-idx %lu)", wksp->name, wksp->page_cnt, wksp->page_sz, fd_shmem_cpu_idx( wksp->numa_idx ) ));
    wksp->wksp            = fd_wksp_new_anonymous( wksp->page_sz,  wksp->page_cnt, fd_shmem_cpu_idx( wksp->numa_idx ), wksp->name, 0UL );
    FD_TEST( wksp->wksp );
    ulong offset          = fd_wksp_alloc( wksp->wksp, fd_topo_workspace_align(), wksp->known_footprint, 1UL );
    if( FD_UNLIKELY( !offset ) ) FD_LOG_ERR(( "fd_wksp_alloc failed" ));
    /* FIXME assert offset==gaddr_lo */

    // fd_topo_join_workspace( &config->topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* DO NOT USE - leave as reference */
    fd_topo_wksp_new( &config->topo, wksp, CALLBACKS );
    fd_topo_workspace_fill( &config->topo, wksp );
    // fd_topo_leave_workspace( &config->topo, wksp ); /* DO NOT USE - leave as reference */
  }

  /* Fill tile. */
  fd_topo_tile_t * test_tile = NULL;
  for( ulong i=0; i<config->topo.tile_cnt; i++ ) {
    if( !strcmp( config->topo.tiles[ i ].name, "pack" ) ) {
      test_tile = &config->topo.tiles[ i ];
      break;
    }
  }
  FD_TEST( test_tile );
  // fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* DO NOT USE - leave as reference */
  // fd_topo_join_tile_workspaces( &config->topo, test_tile ); /* DO NOT USE - leave as reference */
  fd_topo_fill_tile( &config->topo, test_tile );
  // initialize_stacks( config );  /* DO NOT USE - leave as reference */

  /* Kind of a hack */
  fd_metrics_register( fd_metrics_new( metrics_scratch, 10, 10 ) );

  /* [tile-unit-test] unprivileged_init. */
  unprivileged_init( &config->topo, test_tile );

  /* [tile-unit-test] config tile-unit-test. */
  ulong topo_pack_tile_idx        = fd_topo_find_tile( &config->topo, "pack", 0UL );
  FD_TEST( topo_pack_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * topo_pack_tile = &config->topo.tiles[ topo_pack_tile_idx ];
  FD_TEST( topo_pack_tile );

  fd_pack_ctx_t * pack_ctx = fd_topo_obj_laddr( &config->topo, topo_pack_tile->tile_obj_id );
  FD_TEST( pack_ctx );

  /* PoH in-link */
  ulong poh_link_idx          = fd_topo_find_link( &config->topo, "poh_pack", 0UL );
  FD_TEST( poh_link_idx!=ULONG_MAX );
  fd_topo_link_t * poh_link   = &config->topo.links[ poh_link_idx ];
  void * poh_link_base        = fd_wksp_containing( poh_link->dcache );
  FD_TEST( poh_link_base );
  ulong poh_seq = 0UL;
  fd_frag_meta_t * poh_mcache = poh_link->mcache;
  ulong const poh_depth       = fd_mcache_depth( poh_mcache );
  ulong const poh_chunk0      = fd_dcache_compact_chunk0( poh_link_base, poh_link->dcache );
  ulong const poh_wmark       = fd_dcache_compact_wmark ( poh_link_base, poh_link->dcache, poh_link->mtu );
  ulong       poh_chunk       = poh_chunk0;

  /* Resolve in-link */
  ulong resolve_link_idx          = fd_topo_find_link( &config->topo, "resolv_pack", 0UL );
  FD_TEST( resolve_link_idx!=ULONG_MAX );
  fd_topo_link_t * resolve_link   = &config->topo.links[ resolve_link_idx ];
  void * resolve_link_base        = fd_wksp_containing( resolve_link->dcache );
  FD_TEST( resolve_link_base );
  ulong resolve_seq               = 0UL;
  fd_frag_meta_t * resolve_mcache = resolve_link->mcache;
  ulong const resolve_depth       = fd_mcache_depth( resolve_mcache );
  ulong const resolve_chunk0      = fd_dcache_compact_chunk0( resolve_link_base, resolve_link->dcache );
  ulong const resolve_wmark       = fd_dcache_compact_wmark ( resolve_link_base, resolve_link->dcache, resolve_link->mtu );
  ulong       resolve_chunk       = resolve_chunk0;

  /* Bank out-link */
  ulong bank_link_idx          = fd_topo_find_link( &config->topo, "pack_bank", 0UL );
  FD_TEST( bank_link_idx!=ULONG_MAX );
  fd_topo_link_t * bank_link   = &config->topo.links[ bank_link_idx ];
  void * bank_link_base        = fd_wksp_containing( bank_link->dcache );
  FD_TEST( bank_link_base );
  ulong bank_seq               = 0UL;
  fd_frag_meta_t * bank_mcache = bank_link->mcache;
  ulong const bank_depth       = fd_mcache_depth( bank_mcache );
  // ulong const bank_chunk0      = fd_dcache_compact_chunk0( bank_link_base, bank_link->dcache );
  // ulong const bank_wmark       = fd_dcache_compact_wmark ( bank_link_base, bank_link->dcache, bank_link->mtu );

  /* Some Hacks: */
  pack_ctx->use_consumed_cus = 0; // Not rebate. avoid skipping txnes
  for( ulong i=1; i<sizeof(pack_ctx->wait_duration_ticks)/sizeof(pack_ctx->wait_duration_ticks[0]); ++i ) pack_ctx->wait_duration_ticks[i] = 10;   // no waiting between scheduling txn

  ulong stem_min_cr_avail        = ULONG_MAX;
  ulong stem_mcache_depth[2]     = { bank_depth,  poh_depth  };
  ulong stem_cr_avil[2]          = { ULONG_MAX,   ULONG_MAX  };
  ulong stem_seq[2]              = { bank_seq,    poh_seq    };
  fd_frag_meta_t* stem_mcache[2] = { bank_mcache, poh_mcache };
  fd_stem_context_t stem = {
    .min_cr_avail = &stem_min_cr_avail,
    .cr_avail     = stem_cr_avil,
    .depths       = stem_mcache_depth,
    .mcaches      = stem_mcache,
    .seqs         = stem_seq
  };

  int txn_i                 = 0;
  int txn_ref_i             = 0;  // reference txn to check against
  int txn_in_pack           = 0;  // number of txnes currently stored in pack
  int txn_in_pack_at_leader = 2;  // least number of txnes stored in pack when becoming the leader.

  const char empty_w_acc[1] = {0};

  /* [tile-unit-test] Bundle */
  FD_LOG_NOTICE(( "--------------------[tile-unit-test] Bundle----------------------" ));
  for( int txn_per_bundle = FD_PACK_MAX_TXN_PER_BUNDLE; txn_per_bundle>=1; txn_per_bundle--  ) {
    ulong bundle_id        = (ulong)txn_per_bundle;  // current bundle id
    int bundle_txn_i_start = (int)txn_i;
    int bundle_txn_i_end   = (int)txn_i + txn_per_bundle;
    make_bundle( txn_per_bundle, bundle_txn_i_start );

    /* publish the bundle */
    while( (int)txn_i<bundle_txn_i_end ) {
      fd_txn_p_t * txnp    = &txn_scratch[txn_i];
      fd_txn_t   * txn     = TXN( txnp );
      txnp_sz[txn_i]       = txnp->payload_sz;
      FD_TEST( txnp_sz[txn_i] );
      txnt_sz[txn_i]       = (ushort) fd_txn_footprint( txn->instr_cnt, txn->addr_table_adtl_cnt );
      fd_txn_m_t * txnm    = (fd_txn_m_t *) fd_chunk_to_laddr( resolve_link_base, resolve_chunk );
      txnm->payload_sz     = (ushort) txnp_sz[txn_i];
      txnm->txn_t_sz       = (ushort) txnt_sz[txn_i];
      fd_memcpy( fd_txn_m_payload( txnm ), txnp,  sizeof(fd_txn_p_t) );
      fd_memcpy( fd_txn_m_txn_t(   txnm ), txn,   txnm->txn_t_sz     );
      ulong txnm_footprint = fd_txn_m_realized_footprint( txnm, 1, 0 );
      /* bundle block engine */
      txnm->block_engine.bundle_id      = bundle_id;
      txnm->block_engine.bundle_txn_cnt = (ulong)txn_per_bundle;
      txnm->block_engine.commission     = COMMISSION;
      fd_memcpy( txnm->block_engine.commission_pubkey, COMMISSION_PUBKEY, 32 );

      fd_mcache_publish( resolve_mcache, resolve_depth, resolve_seq, 0, resolve_chunk, txnm_footprint, 0, 0, 0 );

      ulong in_idx   = IN_KIND_RESOLV;
      ulong in_sig   = 0;               // for testing. should be the blockhash from resolve tile
      ulong in_sz    = txnm_footprint;
      ulong in_chunk = resolve_chunk;

      resolve_chunk = fd_dcache_compact_next( resolve_chunk, txnm_footprint, resolve_chunk0, resolve_wmark  );
      resolve_seq   = fd_seq_inc( resolve_seq, 1 );
      txn_i++;

      // before/after_credit should be like a no-op right now since we don't test overrun and haven't became a leader yet
      int charge_busy = 1;
      FD_LOG_NOTICE(( "before_credit %d", txn_i-1 ));
      before_credit( pack_ctx, &stem, &charge_busy );
      FD_LOG_NOTICE(( "after_credit %d", txn_i-1 ));
      after_credit( pack_ctx, &stem, 0, &charge_busy );

      FD_LOG_NOTICE(( "during_frag %d", txn_i-1 ));
      during_frag( pack_ctx, in_idx, 0, in_sig, in_chunk, in_sz, 0 );

      /* Verify insertion from pack_ctx */
      FD_TEST( pack_ctx->is_bundle                                                               );
      FD_TEST( pack_ctx->current_bundle->id                ==bundle_id                           );
      FD_TEST( pack_ctx->current_bundle->txn_cnt           ==(ulong)txn_per_bundle               );
      FD_TEST( pack_ctx->current_bundle->txn_received      ==(ulong)(txn_i-bundle_txn_i_start-1) );
      FD_TEST( pack_ctx->current_bundle->min_blockhash_slot==in_sig                              );

      FD_TEST( pack_ctx->blk_engine_cfg->commission==COMMISSION                                             );
      FD_TEST( fd_memeq( pack_ctx->blk_engine_cfg->commission_pubkey->b, COMMISSION_PUBKEY, 32 ) );

      fd_txn_p_t * txnp_during_frag = &txn_scratch[ txn_i-1 ];
      FD_TEST( pack_ctx->cur_spot->txnp->payload_sz==txnp_sz[ txn_i-1 ]                            );
      FD_TEST( fd_memeq( pack_ctx->cur_spot->txnp->payload, txnp_during_frag,  txnp_sz[ txn_i-1 ] ) );
      FD_TEST( fd_memeq( TXN(pack_ctx->cur_spot->txnp), TXN(txnp_during_frag), txnt_sz[ txn_i-1 ] ) );

      FD_LOG_NOTICE(( "after_frag %d", txn_i-1 ));
      after_frag( pack_ctx, in_idx, 0, in_sig, 0, 0, 0, &stem );

      // Hack:
      pack_ctx->skip_cnt         = 0;  // no skipping block
      pack_ctx->bank_idle_bitset = 1;  // bank is always "idle"
    }

    fd_pack_set_initializer_bundles_ready( pack_ctx->pack );

    // Mock PoH tile: become the leader
    FD_LOG_NOTICE(( "Bundle Ieration %lu: IN_KIND_POH", bundle_id ));
    fd_became_leader_t * leader = (fd_became_leader_t *) fd_chunk_to_laddr( poh_link_base, poh_chunk );
    make_leader( leader );

    ulong in_idx   = IN_KIND_POH;
    ulong in_chunk = poh_chunk;
    ulong in_sz    = sizeof(fd_became_leader_t);
    ulong in_sig   = fd_disco_poh_sig( (ulong)bundle_id, POH_PKT_TYPE_BECAME_LEADER, 0UL );

    poh_chunk = fd_dcache_compact_next( poh_chunk, sizeof(fd_became_leader_t), poh_chunk0, poh_wmark );
    poh_seq   = fd_seq_inc( poh_seq, 1 );

    // before/after_credit should be like a no-op right now since we don't test overrun and haven't became a leader yet
    int charge_busy = 1;
    FD_LOG_NOTICE(( "before_credit %lu", bundle_id ));
    before_credit( pack_ctx, &stem, &charge_busy );   // should be like a no-op right now since we don't test overrun yet
    FD_LOG_NOTICE(( "after_credit %lu", bundle_id ));
    after_credit( pack_ctx, &stem, 0, &charge_busy );

    FD_LOG_NOTICE(( "during_frag %lu", bundle_id ));
    during_frag( pack_ctx, in_idx, 0, in_sig, in_chunk, in_sz, 0 );
    /* Verify became_leader is copied over */
    FD_TEST( fd_memeq( pack_ctx->_became_leader, leader, sizeof(fd_became_leader_t) ) );

    FD_LOG_NOTICE(( "after_frag %lu", bundle_id ));
    after_frag( pack_ctx, in_idx, 0, in_sig, 0, 0, 0, &stem );
    FD_TEST( pack_ctx->leader_slot!=ULONG_MAX );

    // Hack:
    pack_ctx->skip_cnt         = 0;  // no skipping block
    pack_ctx->bank_idle_bitset = 1;  // bank is always "idle"

    after_credit( pack_ctx, &stem, 0, &charge_busy );

    /* Test publishing to bank (logic taken by fd_bank_tile.c) */
    fd_frag_meta_t * bank_mline        = bank_mcache + fd_mcache_line_idx( bank_seq, bank_depth );
    ushort           mline_sz          = bank_mline->sz;
    ulong            bank_dcache_entry = (ulong)fd_chunk_to_laddr( bank_link_base, bank_mline->chunk ) + bank_mline->ctl;
    int              txnp_cnt_out      = (int)((mline_sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t));
    fd_txn_p_t     * txnp_out          = (fd_txn_p_t *) bank_dcache_entry;
    FD_TEST( txnp_out );
    FD_TEST( txnp_cnt_out==txn_per_bundle );
    for( int txnp_out_i=0; txnp_out_i<txn_per_bundle; txnp_out_i++ ) {
      fd_txn_p_t     * txnp              = &txn_scratch[ txn_ref_i ];
      ulong            payload_sz        = txnp_sz[      txn_ref_i ];
      if( ( txnp_out->payload_sz!=payload_sz ) ||
        !fd_memeq( txnp, txnp_out, txnp_out->payload_sz ) ) {
      FD_LOG_HEXDUMP_NOTICE(( "txnp",     txnp,      payload_sz           ));
      FD_LOG_HEXDUMP_ERR((    "txnp_out", txnp_out,  txnp_out->payload_sz ));
      }
      fd_txn_t * txn_out      = TXN( txnp_out );
      fd_txn_t * txn          = TXN( txnp );
      ulong txn_t_sz          = txnt_sz[ txn_ref_i ];
      ulong txn_t_sz_out      = (ushort) fd_txn_footprint( txn_out->instr_cnt, txn_out->addr_table_adtl_cnt );
      FD_TEST( txn_t_sz_out==txn_t_sz );
      if( ( txn_t_sz_out!=txn_t_sz ) ||
          !fd_memeq( txn, txn_out, txn_t_sz_out ) ) {
        FD_LOG_HEXDUMP_NOTICE(( "txn",     &txn,     txn_t_sz     ));
        FD_LOG_HEXDUMP_ERR((    "txn_out", &txn_out, txn_t_sz_out ));
      }

      txnp_out++;
      txn_ref_i++;
    }

    // bank chunk incremented in after_credit
    bank_seq      = fd_seq_inc( bank_seq,    1 );

    FD_LOG_NOTICE(( "bank out memory verified" ));

    /* manual housekeeping */
    pack_ctx->approx_wallclock_ns = fd_log_wallclock();
    // Hack:
    pack_ctx->skip_cnt         = 0;  // no skipping block
    pack_ctx->bank_idle_bitset = 1;  // bank is always "idle"
    fd_memset( pack_ctx->wait_duration_ticks, 0, sizeof( pack_ctx->wait_duration_ticks ) );

    pack_ctx->leader_slot = ULONG_MAX;
  }


  /* [tile-unit-test] Normal I/O*/
  FD_LOG_NOTICE(( "--------------------[tile-unit-test] Normal I/O----------------------" ));
  fd_memset( txn_scratch, 0, sizeof(txn_scratch) );
  txn_i      = 0;
  txn_ref_i  = 0;
  int loop_i = 0;
  while( txn_i < MAX_TEST_TXNS ) {
    fd_became_leader_t * leader = NULL;

    ulong in_idx;
    ulong in_sz;
    ulong in_chunk;
    ulong in_sig    = 0;

    if( ( pack_ctx->leader_slot==ULONG_MAX ) && ( txn_in_pack>=txn_in_pack_at_leader ) ) {
      // Mock PoH tile: become the leader
      FD_LOG_NOTICE(( "Ieration %d: IN_KIND_POH", loop_i ));
      in_idx   = IN_KIND_POH;
      in_chunk = poh_chunk;
      in_sz    = sizeof(fd_became_leader_t);
      in_sig   = fd_disco_poh_sig( (ulong)loop_i, POH_PKT_TYPE_BECAME_LEADER, 0UL );

      leader = (fd_became_leader_t *) fd_chunk_to_laddr( poh_link_base, poh_chunk );
      make_leader( leader );

      epoch++;

    } else {
      FD_LOG_NOTICE(( "Ieration %d: IN_KIND_RESOLV", loop_i ));
      // Mock resolve tile: publish a transaction
      in_idx = IN_KIND_RESOLV;

      make_transaction( &txn_scratch[txn_i], (ulong)txn_i, empty_w_acc, accs[ txn_i ] );
      fd_txn_p_t * txnp    = &txn_scratch[txn_i];
      fd_txn_t   * txn     = TXN( txnp );
      txnp_sz[txn_i]       = txnp->payload_sz;
      txnt_sz[txn_i]       = (ushort) fd_txn_footprint( txn->instr_cnt, txn->addr_table_adtl_cnt );
      fd_txn_m_t * txnm    = (fd_txn_m_t *) fd_chunk_to_laddr( resolve_link_base, resolve_chunk );
      txnm->payload_sz     = (ushort) txnp_sz[txn_i];
      txnm->txn_t_sz       = (ushort) txnt_sz[txn_i];
      fd_memcpy( fd_txn_m_payload( txnm ), txnp,  txnm->payload_sz );
      fd_memcpy( fd_txn_m_txn_t(   txnm ), txn,   txnm->txn_t_sz   );
      ulong txnm_footprint = fd_txn_m_realized_footprint( txnm, 1, 0 );
      fd_mcache_publish( resolve_mcache, resolve_depth, resolve_seq, 0, resolve_chunk, txnm_footprint, 0, 0, 0 );
      txn_i++;

      in_sz    = txnm_footprint;
      in_chunk = resolve_chunk;

      resolve_chunk = fd_dcache_compact_next( resolve_chunk, txnm_footprint, resolve_chunk0, resolve_wmark  );
      resolve_seq   = fd_seq_inc( resolve_seq, 1 );
    }

    int charge_busy = 1;
    FD_LOG_NOTICE(( "before_credit %d", loop_i ));
    before_credit( pack_ctx, &stem, &charge_busy );   // should be like a no-op right now since we don't test overrun yet

    FD_LOG_NOTICE(( "after_credit %d", loop_i ));
    after_credit( pack_ctx, &stem, 0, &charge_busy );
    if( pack_ctx->leader_slot!=ULONG_MAX ){
      /* Test publishing to bank (logic taken by fd_bank_tile.c) */
      fd_frag_meta_t * bank_mline        = bank_mcache + fd_mcache_line_idx( bank_seq, bank_depth );
      ushort           mline_sz          = bank_mline->sz;
      ulong            bank_dcache_entry = (ulong)fd_chunk_to_laddr( bank_link_base, bank_mline->chunk ) + bank_mline->ctl;
      int              txnp_cnt_out      = (int)((mline_sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t));
      fd_txn_p_t     * txnp_out          = (fd_txn_p_t *) bank_dcache_entry;
      fd_txn_p_t     * txnp              = &txn_scratch[ txn_ref_i ];
      ulong            payload_sz        = txnp_sz[      txn_ref_i ];
      FD_TEST( txnp_out );
      FD_TEST( txnp_cnt_out==EFFECTIVE_TXN_PER_MICROBLOCK );
      if( ( txnp_out->payload_sz!=payload_sz ) ||
          !fd_memeq( txnp, txnp_out, txnp_out->payload_sz ) ) {
        FD_LOG_HEXDUMP_NOTICE(( "txnp",     txnp,      payload_sz           ));
        FD_LOG_HEXDUMP_ERR((    "txnp_out", txnp_out,  txnp_out->payload_sz ));
      }
      fd_txn_t * txn_out      = TXN( txnp_out );
      fd_txn_t * txn          = TXN( txnp );
      ulong txn_t_sz          = txnt_sz[ txn_ref_i ];
      ulong txn_t_sz_out      = (ushort) fd_txn_footprint( txn_out->instr_cnt, txn_out->addr_table_adtl_cnt );
      FD_TEST( txn_t_sz_out==txn_t_sz );
      if( ( txn_t_sz_out!=txn_t_sz ) ||
          !fd_memeq( txn, txn_out, txn_t_sz_out ) ) {
        FD_LOG_HEXDUMP_NOTICE(( "txn",     &txn,     txn_t_sz     ));
        FD_LOG_HEXDUMP_ERR((    "txn_out", &txn_out, txn_t_sz_out ));
      }

      // bank chunk incremented in after_credit
      bank_seq      = fd_seq_inc( bank_seq,    1 );

      FD_LOG_NOTICE(( "bank out memory verified" ));

      txn_ref_i++;
      txn_in_pack--;

      // Hack:
      pack_ctx->skip_cnt         = 0;  // no skipping block
      pack_ctx->bank_idle_bitset = 1;  // bank is always "idle"
    }

    FD_LOG_NOTICE(( "during_frag %d", loop_i ));
    during_frag( pack_ctx, in_idx, 0, in_sig, in_chunk, in_sz, 0 );
    if( in_idx==IN_KIND_RESOLV ) {
      /* Verify insertion from pack_ctx */
      fd_txn_p_t * txnp = &txn_scratch[ txn_i-1 ];
      FD_TEST( pack_ctx->cur_spot->txnp->payload_sz==txnp_sz[ txn_i-1 ]                            );
      FD_TEST( fd_memeq( pack_ctx->cur_spot->txnp->payload, txnp,  txnp_sz[ txn_i-1 ] ) );
      FD_TEST( fd_memeq( TXN(pack_ctx->cur_spot->txnp), TXN(txnp), txnt_sz[ txn_i-1 ] ) );

    } else if( in_idx==IN_KIND_POH ) {
      /* Verify became_leader is copied over */
      FD_TEST( fd_memeq( pack_ctx->_became_leader, leader, sizeof(fd_became_leader_t) ) );

      poh_chunk = fd_dcache_compact_next( poh_chunk, in_sz, poh_chunk0, poh_wmark );
      poh_seq   = fd_seq_inc( poh_seq, 1 );
    } else {
      FD_LOG_ERR(( "untested in idx: %lu", in_idx ));
    }

    FD_LOG_NOTICE(( "after_frag %d", loop_i ));
    after_frag( pack_ctx, in_idx, 0, in_sig, 0, 0, 0, &stem );
    if( in_idx==IN_KIND_POH ) {
      FD_TEST( pack_ctx->leader_slot!=ULONG_MAX );
    } else {
      txn_in_pack++;
    }

    /* manual housekeeping */
    pack_ctx->approx_wallclock_ns = fd_log_wallclock();

    loop_i++;
  }

  /* Tear down tile-unit-test. */
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
