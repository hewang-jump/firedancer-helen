#include "fd_dstipfltr_netlink.h"
#include "fd_netlink1.h"
#include <sys/socket.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include "../../util/net/fd_ip4.h"

int
fd_netlink_dstipfltr_check( fd_dstipfltr_hmap_t * hmap,
                            uint dst_ip,
                            fd_dstipfltr_params_t * filter ) {
  FD_LOG_NOTICE(( "querying addr " FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( dst_ip )  ));
  uint key = dst_ip;
  fd_dstipfltr_hmap_query_t query[1];
  fd_dstipfltr_hmap_entry_t sentinel[1];
  int find_res = fd_dstipfltr_hmap_query_try( hmap, &key, sentinel, query, 0 );
  if( find_res==FD_MAP_SUCCESS ) {
    fd_dstipfltr_hmap_entry_t const * ele = fd_dstipfltr_hmap_query_ele_const( query );
    fd_dstipfltr_params_t fltr = ele->fltr_params;
    find_res = fd_dstipfltr_hmap_query_test( query );
    if( FD_UNLIKELY( find_res!=FD_MAP_SUCCESS ) ) return 0;
    fd_memcpy( filter, &fltr, sizeof(fd_dstipfltr_params_t) );
    FD_LOG_NOTICE(( "found" ));
    return 1;
  }
  return 0;
}


int
fd_netlink_dstipfltr_load( fd_netlink_t * netlink,
                           fd_dstipfltr_hmap_t * hmap ) {
  FD_LOG_NOTICE(( "fd_netlink_get_all_ips" ));
  uint seq = netlink->seq++;
  struct {
    struct nlmsghdr nlh;  /* Netlink header */
    struct ifaddrmsg addrmsg;
  } request;
  request.nlh = (struct nlmsghdr) {
    .nlmsg_type  = RTM_GETADDR,
    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .nlmsg_len   = sizeof(request),
    .nlmsg_seq   = seq
  };
  request.addrmsg = (struct ifaddrmsg) {
    .ifa_family = AF_INET, /* IPv4 */
    .ifa_scope = RT_SCOPE_UNIVERSE
  };

  long send_res = sendto( netlink->fd, &request, sizeof(request), 0, NULL, 0 );

  if( FD_UNLIKELY( send_res<0 ) ) {
    FD_LOG_WARNING(( "netlink send(%d,RTM_GETADDR,NLM_F_REQUEST|NLM_F_DUMP) failed (%d-%s)", netlink->fd, errno, fd_io_strerror( errno ) ));
    return errno;
  }
  if( FD_UNLIKELY( send_res!=sizeof(request) ) ) {
    FD_LOG_WARNING(( "netlink send(%d,RTM_GETADDR,NLM_F_REQUEST|NLM_F_DUMP) failed (short write)", netlink->fd ));
    return EPIPE;
  }

  int inserted_ips = 0;

  uchar buf[ 4096 ];
  fd_netlink_iter_t iter[1];
  for( fd_netlink_iter_init( iter, netlink, buf, sizeof(buf) );
       !fd_netlink_iter_done( iter );
       fd_netlink_iter_next( iter, netlink ) ) {
    struct nlmsghdr const * nlh = fd_netlink_iter_msg( iter );
    if( FD_UNLIKELY( nlh->nlmsg_flags & NLM_F_DUMP_INTR ) ) FD_LOG_NOTICE(( "dump inconsistent" ));
    if( FD_UNLIKELY( nlh->nlmsg_type==NLMSG_ERROR ) ) {
      struct nlmsgerr * err = NLMSG_DATA( nlh );
      int nl_err = -err->error;
      FD_LOG_WARNING(( "netlink RTM_GETADDR,NLM_F_REQUEST|NLM_F_DUMP failed (%d-%s)", nl_err, fd_io_strerror( nl_err ) ));
      return nl_err;
    }
    if( FD_UNLIKELY( nlh->nlmsg_type!=RTM_NEWADDR ) ) {
      FD_LOG_DEBUG(( "unexpected nlmsg_type %u", nlh->nlmsg_type ));
      continue;
    }


    struct ifaddrmsg * msg = NLMSG_DATA( nlh ) ;
    struct rtattr    * rat = IFA_RTA( msg );
    ulong rat_sz           = IFA_PAYLOAD( nlh );

    FD_LOG_HEXDUMP_NOTICE(( "rat", rat, rat_sz ));

    uint flags = 0;
    uint local_addrs = UINT_MAX;
    uint scope = msg->ifa_scope;

    for(; RTA_OK( rat, rat_sz ); rat=RTA_NEXT( rat, rat_sz ) ) {
      void * rta   = RTA_DATA( rat );
      switch( rat->rta_type ) {   // nla_type
      case IFA_LOCAL: {
        local_addrs = FD_LOAD( uint, rta );
        break;
      }
      case IFA_FLAGS: {
        uint ifa_flags = FD_LOAD( uint, rta );
        if( !((ifa_flags & IFA_F_PERMANENT) || (ifa_flags & IFA_F_NOPREFIXROUTE))  ) continue;
        flags = ifa_flags;
        FD_LOG_NOTICE(( "flags: %u", flags ));
        break;
      }
      }
    }
    if( local_addrs==UINT_MAX ) continue;

    uint key = local_addrs;
    fd_dstipfltr_hmap_query_t query[1];
    fd_dstipfltr_hmap_entry_t sentinel[1];
    int err = fd_dstipfltr_hmap_prepare( hmap, &key, sentinel, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( err==FD_MAP_ERR_FULL ) ) return FD_MAP_ERR_FULL;   // Has probed longer than prob max.
    else if ( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_dstfilter_hmap_prepare failed. err: %d", err ));

    fd_dstipfltr_hmap_entry_t * ele = fd_dstipfltr_hmap_query_ele( query );
    ele->dst_ip                     = local_addrs;
    ele->fltr_params.flags          = flags;
    ele->fltr_params.scope          = scope;

    fd_dstipfltr_hmap_publish( query );

    FD_LOG_NOTICE(( "addrs " FD_IP4_ADDR_FMT " published", FD_IP4_ADDR_FMT_ARGS( local_addrs ) ));

    inserted_ips++;
  }

  return inserted_ips;
}



void *
fd_netlink_dstipfltr_join( fd_dstipfltr_hmap_t * hmap,
                           void * shmem ) {

  void * hmap_mem = shmem;
  void * hmap_ele_mem = (void *) ( (ulong)hmap_mem + fd_dstipfltr_hmap_footprint( DSTIPFLTR_HMAP_MAX, DSTIPFLTR_HMAP_LOCK_CNT, DSTIPFLTR_HMAP_MAX ) );
  return fd_dstipfltr_hmap_join( hmap, hmap_mem, hmap_ele_mem );
}
