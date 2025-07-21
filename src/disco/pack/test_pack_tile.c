#include "fd_microblock.h"
#include "fd_pack.h"
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

#include "fd_pack_tile.c"
#include "fd_pack_cost.h"
const char SIGNATURE_SUFFIX[ FD_TXN_SIGNATURE_SZ - sizeof(ulong) - sizeof(uint) ] = ": this is the fake signature of transaction number ";
const char WORK_PROGRAM_ID[ FD_TXN_ACCT_ADDR_SZ ] = "Work Program Id Consumes 1<<j CU";

const char * accs[10] = {
  "A",
  "B",
  "C",
  "D",
  "E",
  "G",
  "H",
  "I",
  "J",
  "K",
};

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
   payload_scratch[ i ].  If priority_fees is non-null, it will contain
   the priority fee in lamports. If pack_cost_estimate is non-null, it
   will contain the cost estimate used by pack when packing blocks. */
static void
make_transaction1( fd_txn_p_t * txnp,
                   ulong        i,
                   uint         compute,
                   uint         loaded_data_sz,
                   double       priority,
                   char const * writes,
                   char const * reads,
                   ulong *      priority_fees,
                   ulong *      pack_cost_estimate ) {
  uchar * p = txnp->payload;
  uchar * p_base = p;
  fd_txn_t * t = TXN( txnp );

  *(p++) = (uchar)1;
  fd_memcpy( p,                                   &i,               sizeof(ulong)                                    );
  fd_memcpy( p+sizeof(ulong),                     SIGNATURE_SUFFIX, FD_TXN_SIGNATURE_SZ - sizeof(ulong)-sizeof(uint) );
  fd_memcpy( p+FD_TXN_SIGNATURE_SZ-sizeof(ulong), &compute,         sizeof(uint)                                     );
  p += FD_TXN_SIGNATURE_SZ;
  t->transaction_version = FD_TXN_VLEGACY;
  t->signature_cnt = 1;
  t->signature_off = 1;
  t->message_off = FD_TXN_SIGNATURE_SZ+1UL;
  t->readonly_signed_cnt = 0;
  ulong programs_to_include = 2UL; /* 1 for compute budget, 1 for "work" program */
  t->readonly_unsigned_cnt = (uchar)(strlen( reads ) + programs_to_include);
  t->acct_addr_cnt = (ushort)(1UL + strlen( reads ) + programs_to_include + strlen( writes ));
  t->acct_addr_off = FD_TXN_SIGNATURE_SZ+1UL;

  /* Add the signer */
  *p = 's' + 0x80; fd_memcpy( p+1, &i, sizeof(ulong) ); memset( p+9, 'S', FD_TXN_ACCT_ADDR_SZ-9 ); p += FD_TXN_ACCT_ADDR_SZ;
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

  t->recent_blockhash_off = 0;
  t->addr_table_lookup_cnt = 0;
  t->addr_table_adtl_writable_cnt = 0;
  t->addr_table_adtl_cnt = 0;
  t->instr_cnt = (ushort)(3UL + (ulong)fd_uint_popcnt( compute ));
  uchar prog_start = (uchar)(1UL+strlen( writes ));

  t->instr[ 0 ].program_id = prog_start;
  t->instr[ 0 ].acct_cnt = 0;
  t->instr[ 0 ].data_sz = 5;
  t->instr[ 0 ].acct_off = (ushort)(p - p_base);
  t->instr[ 0 ].data_off = (ushort)(p - p_base);
  int j = 0;

  /* Write instruction data */
  *p = 2; fd_memcpy( p+1, &compute, sizeof(uint) );
  p += 5UL;

  t->instr[ 1 ].program_id = prog_start;
  t->instr[ 1 ].acct_cnt = 0;
  t->instr[ 1 ].data_sz = 9;
  t->instr[ 1 ].acct_off = (ushort)(p - p_base);
  t->instr[ 1 ].data_off = (ushort)(p - p_base);
  j = 1;

  /* 3 corresponds to SetComputeUnitPrice */
  ulong rewards_per_cu = (ulong) (pow( 5.0, priority )*10000.0 / (double)compute);
  *p = 3; fd_memcpy( p+1, &rewards_per_cu, sizeof(ulong) );
  p += 9UL;

  t->instr[ 2 ].program_id = prog_start;
  t->instr[ 2 ].acct_cnt = 0;
  t->instr[ 2 ].data_sz = 5;
  t->instr[ 2 ].acct_off = (ushort)(p - p_base);
  t->instr[ 2 ].data_off = (ushort)(p - p_base);
  j = 2;

  /* 4 corresponds to SetLoadedAccountsDataSizeLimit */
  *p = 4; fd_memcpy( p+1, &loaded_data_sz, sizeof(uint) );
  p += 5UL;

  j = 3UL;
  for( uint i = 0U; i<32U; i++ ) {
    if( compute & (1U << i) ) {
      *p = (uchar)i;
      t->instr[ j ].program_id = (uchar)(prog_start + 1);
      t->instr[ j ].acct_cnt = 0;
      t->instr[ j ].data_sz = 1;
      t->instr[ j ].acct_off = (ushort)(p - p_base);
      t->instr[ j ].data_off = (ushort)(p - p_base);
      j++;
      p++;
    }
  }
  txnp->payload_sz = (ulong)(p-p_base);
  uint flags;
  fd_ulong_store_if( !!priority_fees, priority_fees, (rewards_per_cu * compute + 999999UL)/1000000UL );

  ulong cost = fd_pack_compute_cost( TXN( txnp ), txnp->payload, &flags, NULL, NULL, NULL, NULL);
  FD_TEST( cost );

  fd_ulong_store_if( !!pack_cost_estimate, pack_cost_estimate, cost );
}

/* From test_pack.c: call make_txn(...) */
static void
make_transaction( fd_txn_p_t * txnp,
                  ulong        i,
                  const char * w_accs,
                  const char * r_accs ) {
  ulong reward;
  ulong cost_estimate;

  make_transaction1( txnp, i, 500U, 500U, 11.0, w_accs, r_accs, &reward, &cost_estimate );
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
    wksp->wksp = fd_wksp_new_anonymous( wksp->page_sz,  wksp->page_cnt, fd_shmem_cpu_idx( wksp->numa_idx ), wksp->name, 0UL );
    FD_TEST( wksp->wksp );
    ulong offset = fd_wksp_alloc( wksp->wksp, fd_topo_workspace_align(), wksp->known_footprint, 1UL );
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

  /* [tile-unit-test] unprivileged_init. */
  unprivileged_init( &config->topo, test_tile );

  /* [tile-unit-test] config tile-unit-test. */
  ulong topo_pack_tile_idx = fd_topo_find_tile( &config->topo, "pack", 0UL );
  FD_TEST( topo_pack_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * topo_pack_tile = &config->topo.tiles[ topo_pack_tile_idx ];
  FD_TEST( topo_pack_tile );

  fd_pack_ctx_t * pack_ctx = fd_topo_obj_laddr( &config->topo, topo_pack_tile->tile_obj_id );
  FD_TEST( pack_ctx );

  /* PoH in-link */
  ulong poh_link_idx = fd_topo_find_link( &config->topo, "poh_pack", 0UL );
  FD_TEST( poh_link_idx!=ULONG_MAX );
  fd_topo_link_t * poh_link = &config->topo.links[ poh_link_idx ];
  void * poh_link_base = fd_wksp_containing( poh_link->dcache );
  FD_TEST( poh_link_base );
  ulong poh_seq = 0UL;
  fd_frag_meta_t * poh_mcache = poh_link->mcache;
  ulong const poh_depth  = fd_mcache_depth( poh_mcache );
  ulong const poh_chunk0 = fd_dcache_compact_chunk0( poh_link_base, poh_link->dcache );
  ulong const poh_wmark  = fd_dcache_compact_wmark ( poh_link_base, poh_link->dcache, poh_link->mtu );
//   ulong       poh_chunk  = poh_chunk0;
  FD_LOG_NOTICE(( "Poh: link_base: %p, seq: %lu, depth: %lu, chunk0: %lu, wmark: %lu", poh_link_base, poh_seq, poh_depth, poh_chunk0, poh_wmark ));

  /* Resolve in-link */
  ulong resolve_link_idx = fd_topo_find_link( &config->topo, "resolv_pack", 0UL );
  FD_TEST( resolve_link_idx!=ULONG_MAX );
  fd_topo_link_t * resolve_link = &config->topo.links[ resolve_link_idx ];
  void * resolve_link_base = fd_wksp_containing( resolve_link->dcache );
  FD_TEST( resolve_link_base );
  ulong resolve_seq = 0UL;
  fd_frag_meta_t * resolve_mcache = resolve_link->mcache;
  ulong const resolve_depth  = fd_mcache_depth( resolve_mcache );
  ulong const resolve_chunk0 = fd_dcache_compact_chunk0( resolve_link_base, resolve_link->dcache );
  ulong const resolve_wmark  = fd_dcache_compact_wmark ( resolve_link_base, resolve_link->dcache, resolve_link->mtu );
  ulong       resolve_chunk  = resolve_chunk0;
  FD_LOG_NOTICE(( "Resolve: link_base: %p, seq: %lu, depth: %lu, chunk0: %lu, wmark: %lu", resolve_link_base, resolve_seq, resolve_depth, resolve_chunk0, resolve_wmark ));


  /* Bank out-link */
  ulong bank_link_idx = fd_topo_find_link( &config->topo, "pack_bank", 0UL );
  FD_TEST( bank_link_idx!=ULONG_MAX );
  fd_topo_link_t * bank_link = &config->topo.links[ bank_link_idx ];
  void * bank_link_base = fd_wksp_containing( bank_link->dcache );
  FD_TEST( bank_link_base );
  ulong bank_seq = 0UL;
  fd_frag_meta_t * bank_mcache = bank_link->mcache;
  ulong const bank_depth  = fd_mcache_depth( bank_mcache );
  ulong const bank_chunk0 = fd_dcache_compact_chunk0( bank_link_base, bank_link->dcache );
  ulong const bank_wmark  = fd_dcache_compact_wmark ( bank_link_base, bank_link->dcache, bank_link->mtu );
  FD_LOG_NOTICE(( "bank: bank_mcache: %p, link_base: %p, seq: %lu, depth: %lu, chunk0: %lu, wmark: %lu", (void *)bank_mcache, (void *)bank_link_base, bank_seq, bank_depth, bank_chunk0, bank_wmark ));

  fd_stem_context_t stem;
  fd_frag_meta_t* stem_mcache_ptrs[1] = {bank_mcache};
  stem.mcaches = stem_mcache_ptrs;
  ulong stem_mcache_depth[1] = {bank_depth};
  stem.depths = stem_mcache_depth;
  ulong stem_cr_avil[1] = {ULONG_MAX};
  stem.cr_avail = stem_cr_avil;
  ulong stem_seq[1] = {0};
  stem.seqs = stem_seq;

  /* [tile-unit-test] */
  for( char i=0; i<4; i++ ) {

    // Mock resolve publishing an transaction
    fd_txn_p_t txnp;
    make_transaction( &txnp, (ulong)i, accs[i*2], accs[i*2+1] );
    fd_txn_t * txn       = TXN( &txnp );
    ulong payload_sz     = txnp.payload_sz;
    ulong txn_t_sz       = (ushort) fd_txn_footprint( txn->instr_cnt, txn->addr_table_adtl_cnt );
    fd_txn_m_t * txnm    = (fd_txn_m_t *) fd_chunk_to_laddr( resolve_link_base, resolve_chunk );
    txnm->payload_sz     = (ushort) payload_sz;
    txnm->txn_t_sz       = (ushort) txn_t_sz;
    fd_memcpy( fd_txn_m_payload( txnm ), &txnp, txnm->payload_sz );
    fd_memcpy( fd_txn_m_txn_t(   txnm ), txn,   txnm->txn_t_sz   );
    ulong txnm_footprint = fd_txn_m_realized_footprint( txnm, 1, 0 );
    fd_mcache_publish( resolve_mcache, resolve_depth, resolve_seq, 0, resolve_chunk, txnm_footprint, 0, 0, 0 );

    /* Insertion */
    FD_LOG_NOTICE(( "during_frag %d", i ));
    during_frag( pack_ctx, IN_KIND_RESOLV, 0, 0, resolve_chunk, txnm_footprint, 0 );

    /* Verify from pack_ctx */
    FD_TEST( fd_memeq( pack_ctx->cur_spot->txnp->payload, &txnp,  payload_sz ) );
    FD_TEST( fd_memeq( TXN(pack_ctx->cur_spot->txnp), txn, txn_t_sz  ) );

    /* Finish insertion */
    FD_LOG_NOTICE(( "after_frag %d", i ));
    after_frag( pack_ctx, IN_KIND_RESOLV, 0, 0, 0, 0, 0, &stem );

    /* Test publishing to bank (logic taken by fd_bank_tile.c) */
    int charge_busy = 1;

    after_credit( pack_ctx, &stem, 0, &charge_busy );
    FD_LOG_NOTICE(( "after_credit %d", i ));

    fd_frag_meta_t * bank_mline = bank_mcache + fd_mcache_line_idx( bank_seq, bank_depth );
    FD_TEST( bank_mline );
    ushort mline_sz         = bank_mline->sz;
    ulong bank_dcache_entry = (ulong)fd_chunk_to_laddr( bank_link_base, bank_mline->chunk ) + bank_mline->ctl;
    ulong txn_cnt_out       = (mline_sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t);
    FD_TEST( txn_cnt_out==1 );
    fd_txn_p_t * txnp_out   = (fd_txn_p_t *) bank_dcache_entry;
    FD_TEST( txnp_out );
    FD_TEST( txnp_out->payload_sz==payload_sz );
    if( !fd_memeq( &txnp, txnp_out, txnp_out->payload_sz ) ) {
      FD_LOG_HEXDUMP_NOTICE(( "txnp",     &txnp,     payload_sz ));
      FD_LOG_HEXDUMP_NOTICE(( "txnp_out", &txnp_out, payload_sz ));
      FD_LOG_ERR(("stop"));
    }
    fd_txn_t * txn_out      = TXN( txnp_out );
    FD_TEST( txn_out );
    ulong txn_t_sz_out      = (ushort) fd_txn_footprint( txn_out->instr_cnt, txn_out->addr_table_adtl_cnt );
    FD_TEST( txn_t_sz_out==txn_t_sz );
    if( !fd_memeq( txn, txn_out, txn_t_sz_out ) ) {
      FD_LOG_HEXDUMP_NOTICE(( "txn",     &txn,     txn_t_sz_out ));
      FD_LOG_HEXDUMP_NOTICE(( "txn_out", &txn_out, txn_t_sz_out ));
      FD_LOG_ERR(("stop"));
    }

    resolve_chunk = fd_dcache_compact_next( resolve_chunk, txnm_footprint, resolve_chunk0, resolve_wmark  );
    resolve_seq   = fd_seq_inc( resolve_seq, 1 );

    // bank chunk incremented in after_credit
    bank_seq      = fd_seq_inc( bank_seq,    1 );

  }

  /* Tear down tile-unit-test. */
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
