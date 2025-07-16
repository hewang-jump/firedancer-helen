#include "fd_addrs_hmap.h"
#include "../../util/net/fd_ip4.h"

int
fd_addrs_hmap_find( fd_addrs_hmap_t * hmap,
                    uint dst_ip,
                    fd_addrs_fltr_attrs_t * fltr_attrs_out ) {
  uint key = dst_ip;
  fd_addrs_hmap_query_t query[1];
  fd_addrs_hmap_entry_t sentinel[1] = {0};
  int find_res = fd_addrs_hmap_query_try( hmap, &key, sentinel, query, 0 );
  if( find_res==FD_MAP_SUCCESS ) {
    fd_addrs_hmap_entry_t const * ele = fd_addrs_hmap_query_ele_const( query );
    fd_addrs_fltr_attrs_t fltr = ele->fltr_attrs;
    find_res = fd_addrs_hmap_query_test( query );
    if( FD_UNLIKELY( find_res!=FD_MAP_SUCCESS ) ) return 0;
    FD_TEST( fltr_attrs_out );
    fd_memcpy( fltr_attrs_out, &fltr, sizeof(fd_addrs_fltr_attrs_t) );
    return 1;
  }
  return 0;
}

int
fd_addrs_hmap_insert( fd_addrs_hmap_t * hmap,
                 uint dst_ip,
                 fd_addrs_fltr_attrs_t * fltr_attrs ) {
  uint key = dst_ip;
  fd_addrs_hmap_query_t query[1];
  fd_addrs_hmap_entry_t sentinel[1];
  int err = fd_addrs_hmap_prepare( hmap, &key, sentinel, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err==FD_MAP_ERR_FULL ) ) return 0;   // Map is full.
  else if ( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_dstfilter_hmap_prepare failed. err: %d", err ));

  fd_addrs_hmap_entry_t * ele = fd_addrs_hmap_query_ele( query );
  ele->dst_ip                 = dst_ip;
  FD_TEST( fltr_attrs );
  fd_memcpy( &ele->fltr_attrs, fltr_attrs, sizeof(fd_addrs_fltr_attrs_t) );

  fd_addrs_hmap_publish( query );

  FD_LOG_NOTICE(( "addrs " FD_IP4_ADDR_FMT " published", FD_IP4_ADDR_FMT_ARGS( dst_ip ) ));

  return 1;
}

void
fd_addrs_hmap_reset( fd_addrs_hmap_t * hmap,
                     void * hmap_shmem,
                     void * hmap_shmem_ele ) {
  ulong ignored[ fd_addrs_hmap_lock_max() ];
  ulong ele_max   = fd_addrs_hmap_ele_max( hmap );
  ulong lock_cnt  = fd_addrs_hmap_lock_cnt( hmap );
  ulong probe_max = fd_addrs_hmap_probe_max( hmap );
  ulong seed      = fd_addrs_hmap_seed( hmap );
  FD_TEST( fd_addrs_hmap_lock_range( hmap, 0, lock_cnt, FD_MAP_FLAG_BLOCKING, ignored )==FD_MAP_SUCCESS );
  FD_TEST( fd_addrs_hmap_new( hmap_shmem, ele_max, lock_cnt, probe_max, seed ) );
  fd_memset( hmap_shmem_ele, 0, ele_max*sizeof(fd_addrs_hmap_entry_t) );
}
