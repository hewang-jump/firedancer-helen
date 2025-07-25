#include "fd_vm_syscall.h"

#include "../../../ballet/ed25519/fd_curve25519.h"
#include "../../../ballet/ed25519/fd_ristretto255.h"

int
fd_vm_syscall_sol_curve_validate_point( /**/            void *  _vm,
                                        /**/            ulong   curve_id,
                                        /**/            ulong   point_addr,
                                        FD_PARAM_UNUSED ulong   r3,
                                        FD_PARAM_UNUSED ulong   r4,
                                        FD_PARAM_UNUSED ulong   r5,
                                        /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L871 */
  fd_vm_t * vm = (fd_vm_t *)_vm;
  ulong     ret = 1UL; /* by default return Ok(1) == error */

  uchar const * point = NULL;
  switch( curve_id ) {

  case FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS:

    FD_VM_CU_UPDATE( vm, FD_VM_CURVE25519_EDWARDS_VALIDATE_POINT_COST );
    point = FD_VM_MEM_HADDR_LD( vm, point_addr, FD_VM_ALIGN_RUST_POD_U8_ARRAY, FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ );
    ret = (ulong)!fd_ed25519_point_validate( point ); /* 0 if valid point, 1 if not */
    break;

  case FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO:

    FD_VM_CU_UPDATE( vm, FD_VM_CURVE25519_RISTRETTO_VALIDATE_POINT_COST );
    point = FD_VM_MEM_HADDR_LD( vm, point_addr, FD_VM_ALIGN_RUST_POD_U8_ARRAY, FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ );
    ret = (ulong)!fd_ristretto255_point_validate( point ); /* 0 if valid point, 1 if not */
    break;

  default:
    /* https://github.com/anza-xyz/agave/blob/5b3390b99a6e7665439c623062c1a1dda2803524/programs/bpf_loader/src/syscalls/mod.rs#L919-L928 */
    if( FD_FEATURE_ACTIVE_BANK( vm->instr_ctx->txn_ctx->bank, abort_on_invalid_curve ) ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
      return FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE; /* SyscallError::InvalidAttribute */
    }
  }

  *_ret = ret;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_curve_group_op( void *  _vm,
                                  ulong   curve_id,
                                  ulong   group_op,
                                  ulong   left_input_addr,
                                  ulong   right_input_addr,
                                  ulong   result_point_addr,
                                  ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L928 */
  fd_vm_t * vm = (fd_vm_t *)_vm;
  ulong     ret = 1UL; /* by default return Ok(1) == error */

  /* Note: we don't strictly follow the Rust implementation, but instead combine
     common code across switch cases. Similar to fd_vm_syscall_sol_alt_bn128_group_op. */

/* MATCH_ID_OP allows us to unify 2 switch/case into 1.
   For better readability, we also temp define EDWARDS, RISTRETTO.

   The first time we check that both curve_id and group_op are valid
   with 2 nested switch/case. Using MATCH_ID_OP leads to undesidered
   edge cases. The second time, when we know that curve_id and group_op
   are correct, then we can use MATCH_ID_OP and a single switch/case. */
#define MATCH_ID_OP(crv_id,grp_op) ((crv_id << 4) | grp_op)
#define EDWARDS   FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS
#define RISTRETTO FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO

  ulong cost = 0UL;
  switch( curve_id ) {

  case EDWARDS:
    switch( group_op ) {

    case FD_VM_SYSCALL_SOL_CURVE_ADD:
      cost = FD_VM_CURVE25519_EDWARDS_ADD_COST;
      break;

    case FD_VM_SYSCALL_SOL_CURVE_SUB:
      cost = FD_VM_CURVE25519_EDWARDS_SUBTRACT_COST;
      break;

    case FD_VM_SYSCALL_SOL_CURVE_MUL:
      cost = FD_VM_CURVE25519_EDWARDS_MULTIPLY_COST;
      break;

    default:
      goto invalid_error;
    }
    break;

  case RISTRETTO:
    switch( group_op ) {

    case FD_VM_SYSCALL_SOL_CURVE_ADD:
      cost = FD_VM_CURVE25519_RISTRETTO_ADD_COST;
      break;

    case FD_VM_SYSCALL_SOL_CURVE_SUB:
      cost = FD_VM_CURVE25519_RISTRETTO_SUBTRACT_COST;
      break;

    case FD_VM_SYSCALL_SOL_CURVE_MUL:
      cost = FD_VM_CURVE25519_RISTRETTO_MULTIPLY_COST;
      break;

    default:
      goto invalid_error;
    }
    break;

  default:
    goto invalid_error;
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L944-L947 */
  FD_VM_CU_UPDATE( vm, cost );

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L949-L958 */

  /* Note: left_input_addr is a point for add, sub, BUT it's a scalar for mul.
     However, from a memory mapping perspective it's always 32 bytes, so we unify the code. */
  uchar const * inputL = FD_VM_MEM_HADDR_LD( vm, left_input_addr,   FD_VM_ALIGN_RUST_POD_U8_ARRAY, 32UL );
  uchar const * inputR = FD_VM_MEM_HADDR_LD( vm, right_input_addr,  FD_VM_ALIGN_RUST_POD_U8_ARRAY, FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ );

  switch( MATCH_ID_OP( curve_id, group_op ) ) {

  case MATCH_ID_OP( EDWARDS, FD_VM_SYSCALL_SOL_CURVE_ADD ): {
    fd_ed25519_point_t p0[1], p1[1], r[1];
    if( FD_UNLIKELY( !fd_ed25519_point_frombytes( p0, inputL ) ) ) {
      goto soft_error;
    }
    if( FD_UNLIKELY( !fd_ed25519_point_frombytes( p1, inputR ) ) ) {
      goto soft_error;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1098-L1102 */
    fd_vm_haddr_query_t result_query = {
      .vaddr    = result_point_addr,
      .align    = FD_VM_ALIGN_RUST_POD_U8_ARRAY,
      .sz       = FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ,
      .is_slice = 0,
    };

    fd_vm_haddr_query_t * queries[] = { &result_query };
    FD_VM_TRANSLATE_MUT( vm, queries );

    fd_ed25519_point_add( r, p0, p1 );
    fd_ed25519_point_tobytes( result_query.haddr, r );
    ret = 0UL;
    break;
  }

  case MATCH_ID_OP( EDWARDS, FD_VM_SYSCALL_SOL_CURVE_SUB ): {
    fd_ed25519_point_t p0[1], p1[1], r[1];
    if( FD_UNLIKELY( !fd_ed25519_point_frombytes( p0, inputL ) ) ) {
      goto soft_error;
    }
    if( FD_UNLIKELY( !fd_ed25519_point_frombytes( p1, inputR ) ) ) {
      goto soft_error;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1127-L1131 */
    fd_vm_haddr_query_t result_query = {
      .vaddr    = result_point_addr,
      .align    = FD_VM_ALIGN_RUST_POD_U8_ARRAY,
      .sz       = FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ,
      .is_slice = 0,
    };

    fd_vm_haddr_query_t * queries[] = { &result_query };
    FD_VM_TRANSLATE_MUT( vm, queries );

    fd_ed25519_point_sub( r, p0, p1 );
    fd_ed25519_point_tobytes( result_query.haddr, r );
    ret = 0UL;
    break;
  }

  case MATCH_ID_OP( EDWARDS, FD_VM_SYSCALL_SOL_CURVE_MUL ): {
    fd_ed25519_point_t p[1], r[1];
    if( FD_UNLIKELY( !fd_curve25519_scalar_validate( inputL ) ) ) {
      goto soft_error;
    }
    if( FD_UNLIKELY( !fd_ed25519_point_frombytes( p, inputR ) ) ) {
      goto soft_error;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1156-L1160 */
    fd_vm_haddr_query_t result_query = {
      .vaddr    = result_point_addr,
      .align    = FD_VM_ALIGN_RUST_POD_U8_ARRAY,
      .sz       = FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ,
      .is_slice = 0,
    };

    fd_vm_haddr_query_t * queries[] = { &result_query };
    FD_VM_TRANSLATE_MUT( vm, queries );

    fd_ed25519_scalar_mul( r, inputL, p );
    fd_ed25519_point_tobytes( result_query.haddr, r );
    ret = 0UL;
    break;
  }

  case MATCH_ID_OP( RISTRETTO, FD_VM_SYSCALL_SOL_CURVE_ADD ): {
    fd_ristretto255_point_t p0[1], p1[1], r[1];
    if( FD_UNLIKELY( !fd_ristretto255_point_frombytes( p0, inputL ) ) ) {
      goto soft_error;
    }
    if( FD_UNLIKELY( !fd_ristretto255_point_frombytes( p1, inputR ) ) ) {
      goto soft_error;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1195-L1199 */
    fd_vm_haddr_query_t result_query = {
      .vaddr    = result_point_addr,
      .align    = FD_VM_ALIGN_RUST_POD_U8_ARRAY,
      .sz       = FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ,
      .is_slice = 0,
    };

    fd_vm_haddr_query_t * queries[] = { &result_query };
    FD_VM_TRANSLATE_MUT( vm, queries );

    fd_ristretto255_point_add( r, p0, p1 );
    fd_ristretto255_point_tobytes( result_query.haddr, r );
    ret = 0UL;
    break;
  }

  case MATCH_ID_OP( RISTRETTO, FD_VM_SYSCALL_SOL_CURVE_SUB ): {
    fd_ristretto255_point_t p0[1], p1[1], r[1];
    if( FD_UNLIKELY( !fd_ristretto255_point_frombytes( p0, inputL ) ) ) {
      goto soft_error;
    }
    if( FD_UNLIKELY( !fd_ristretto255_point_frombytes( p1, inputR ) ) ) {
      goto soft_error;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1226-L1230 */
    fd_vm_haddr_query_t result_query = {
      .vaddr    = result_point_addr,
      .align    = FD_VM_ALIGN_RUST_POD_U8_ARRAY,
      .sz       = FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ,
      .is_slice = 0,
    };

    fd_vm_haddr_query_t * queries[] = { &result_query };
    FD_VM_TRANSLATE_MUT( vm, queries );

    fd_ristretto255_point_sub( r, p0, p1 );
    fd_ristretto255_point_tobytes( result_query.haddr, r );
    ret = 0UL;
    break;
  }

  case MATCH_ID_OP( RISTRETTO, FD_VM_SYSCALL_SOL_CURVE_MUL ): {
    fd_ristretto255_point_t p[1], r[1];
    if( FD_UNLIKELY( !fd_curve25519_scalar_validate( inputL ) ) ) {
      goto soft_error;
    }
    if( FD_UNLIKELY( !fd_ristretto255_point_frombytes( p, inputR ) ) ) {
      goto soft_error;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1255-L1259 */
    fd_vm_haddr_query_t result_query = {
      .vaddr    = result_point_addr,
      .align    = FD_VM_ALIGN_RUST_POD_U8_ARRAY,
      .sz       = FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ,
      .is_slice = 0,
    };

    fd_vm_haddr_query_t * queries[] = { &result_query };
    FD_VM_TRANSLATE_MUT( vm, queries );

    fd_ristretto255_scalar_mul( r, inputL, p );
    fd_ristretto255_point_tobytes( result_query.haddr, r );
    ret = 0UL;
    break;
  }

  default:
    /* COV: this can never happen because of the previous switch */
    return FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE; /* SyscallError::InvalidAttribute */
  }

soft_error:
  *_ret = ret;
  return FD_VM_SUCCESS;
#undef MATCH_ID_OP
#undef EDWARDS
#undef RISTRETTO

invalid_error:
  /* https://github.com/anza-xyz/agave/blob/5b3390b99a6e7665439c623062c1a1dda2803524/programs/bpf_loader/src/syscalls/mod.rs#L1135-L1156 */
  if( FD_FEATURE_ACTIVE_BANK( vm->instr_ctx->txn_ctx->bank, abort_on_invalid_curve ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
    return FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE; /* SyscallError::InvalidAttribute */
  }
  *_ret = 1UL;
  return FD_VM_SUCCESS;
}

/* multi_scalar_mul_edwards computes a MSM on curve25519.

   This function is equivalent to
   zk-token-sdk::edwards::multi_scalar_mul_edwards

   https://github.com/solana-labs/solana/blob/v1.17.7/zk-token-sdk/src/curve25519/edwards.rs#L116

   Specifically it takes as input byte arrays and takes care of scalars
   validation and points decompression.  It then invokes ballet MSM
   function fd_ed25519_multi_scalar_mul.  To avoid dynamic allocation,
   the full MSM is done in batches of FD_BALLET_CURVE25519_MSM_BATCH_SZ. */

static fd_ed25519_point_t *
multi_scalar_mul_edwards( fd_ed25519_point_t * r,
                          uchar const *        scalars,
                          uchar const *        points,
                          ulong                cnt ) {
  /* Validate all scalars first (fast) */
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !fd_curve25519_scalar_validate ( scalars + i*FD_VM_SYSCALL_SOL_CURVE_CURVE25519_SCALAR_SZ ) ) ) {
      return NULL;
    }
  }

  /* Static allocation of a batch of decompressed points */
  fd_ed25519_point_t tmp[1];
  fd_ed25519_point_t A[ FD_BALLET_CURVE25519_MSM_BATCH_SZ ];

  fd_ed25519_point_set_zero( r );
  for( ulong i=0UL; i<cnt; i+=FD_BALLET_CURVE25519_MSM_BATCH_SZ ) {
    ulong batch_cnt = fd_ulong_min( cnt-i, FD_BALLET_CURVE25519_MSM_BATCH_SZ );

    /* Decompress (and validate) points */
    for( ulong j=0UL; j<batch_cnt; j++ ) {
      //TODO: use fd_ed25519_point_frombytes_2x
      if( FD_UNLIKELY( !fd_ed25519_point_frombytes( &A[j], points + j*FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ ) ) ) {
        return NULL;
      }
    }

    fd_ed25519_multi_scalar_mul( tmp, scalars, A, batch_cnt );
    fd_ed25519_point_add( r, r, tmp );
    points  += FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ *batch_cnt;
    scalars += FD_VM_SYSCALL_SOL_CURVE_CURVE25519_SCALAR_SZ*batch_cnt;
  }

  return r;
}

/* multi_scalar_mul_ristretto computes a MSM on ristretto255.
   See multi_scalar_mul_edwards for details. */

static fd_ed25519_point_t *
multi_scalar_mul_ristretto( fd_ristretto255_point_t * r,
                            uchar const *             scalars,
                            uchar const *             points,
                            ulong                     cnt ) {
  /* Validate all scalars first (fast) */
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !fd_curve25519_scalar_validate ( scalars + i*FD_VM_SYSCALL_SOL_CURVE_CURVE25519_SCALAR_SZ ) ) ) {
      return NULL;
    }
  }

  /* Static allocation of a batch of decompressed points */
  fd_ristretto255_point_t tmp[1];
  fd_ristretto255_point_t A[ FD_BALLET_CURVE25519_MSM_BATCH_SZ ];

  fd_ristretto255_point_set_zero( r );
  for( ulong i=0UL; i<cnt; i+=FD_BALLET_CURVE25519_MSM_BATCH_SZ ) {
    ulong batch_cnt = fd_ulong_min( cnt-i, FD_BALLET_CURVE25519_MSM_BATCH_SZ );

    /* Decompress (and validate) points */
    for( ulong j=0UL; j<batch_cnt; j++ ) {
      //TODO: use fd_ristretto255_point_frombytes_2x
      if( FD_UNLIKELY( !fd_ristretto255_point_frombytes( &A[j], points + j*FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ ) ) ) {
        return NULL;
      }
    }

    fd_ristretto255_multi_scalar_mul( tmp, scalars, A, batch_cnt );
    fd_ristretto255_point_add( r, r, tmp );
    points  += FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ *batch_cnt;
    scalars += FD_VM_SYSCALL_SOL_CURVE_CURVE25519_SCALAR_SZ*batch_cnt;
  }

  return r;
}

#undef BATCH_MAX

int
fd_vm_syscall_sol_curve_multiscalar_mul( void *  _vm,
                                         ulong   curve_id,
                                         ulong   scalars_addr,
                                         ulong   points_addr,
                                         ulong   points_len,
                                         ulong   result_point_addr,
                                         ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L1129 */
  fd_vm_t * vm = (fd_vm_t *)_vm;
  ulong     ret = 1UL; /* by default return Ok(1) == error */

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L1143-L1151 */
  if( FD_UNLIKELY( points_len > 512 ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );
    return FD_VM_SYSCALL_ERR_INVALID_LENGTH; /* SyscallError::InvalidLength */
  }

  /* Note: we don't strictly follow the Rust implementation, but instead combine
     common code across switch cases. Similar to fd_vm_syscall_sol_alt_bn128_group_op. */

  ulong base_cost = 0UL;
  ulong incremental_cost = 0UL;
  switch( curve_id ) {
  case FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS:
    base_cost = FD_VM_CURVE25519_EDWARDS_MSM_BASE_COST;
    incremental_cost = FD_VM_CURVE25519_EDWARDS_MSM_INCREMENTAL_COST;
    break;

  case FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO:
    base_cost = FD_VM_CURVE25519_RISTRETTO_MSM_BASE_COST;
    incremental_cost = FD_VM_CURVE25519_RISTRETTO_MSM_INCREMENTAL_COST;
    break;

  default:
    /* https://github.com/anza-xyz/agave/blob/5b3390b99a6e7665439c623062c1a1dda2803524/programs/bpf_loader/src/syscalls/mod.rs#L1262-L1271 */
    if( FD_FEATURE_ACTIVE( vm->instr_ctx->txn_ctx->slot, &vm->instr_ctx->txn_ctx->features, abort_on_invalid_curve ) ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
      return FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE; /* SyscallError::InvalidAttribute */
    }
    goto soft_error;
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L1155-L1164 */
  ulong cost = fd_ulong_sat_add(
    base_cost,
    fd_ulong_sat_mul(
      incremental_cost,
      fd_ulong_sat_sub( points_len, 1 )
    )
  );
  FD_VM_CU_UPDATE( vm, cost );

  /* Edge case points_len==0.
     Agave computes the MSM, that returns the point at infinity, and stores the result.
     This means that we have to mem map result, and then set the point at infinity,
     that is 0x0100..00 for Edwards and 0x00..00 for Ristretto. */
  if ( FD_UNLIKELY( points_len==0 ) ) {
    uchar * result = FD_VM_MEM_HADDR_ST( vm, result_point_addr, FD_VM_ALIGN_RUST_POD_U8_ARRAY, FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ );
    memset( result, 0, 32 );
    result[0] = curve_id==FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS ? 1 : 0;
    *_ret = 0;
    return FD_VM_SUCCESS;
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L1166-L1178 */
  uchar const * scalars = FD_VM_MEM_HADDR_LD( vm, scalars_addr, FD_VM_ALIGN_RUST_POD_U8_ARRAY, points_len*FD_VM_SYSCALL_SOL_CURVE_CURVE25519_SCALAR_SZ );
  uchar const * points  = FD_VM_MEM_HADDR_LD( vm, points_addr,  FD_VM_ALIGN_RUST_POD_U8_ARRAY, points_len*FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ );

  switch( curve_id ) {

  case FD_VM_SYSCALL_SOL_CURVE_CURVE25519_EDWARDS: {
    /* https://github.com/anza-xyz/agave/blob/v1.18.8/programs/bpf_loader/src/syscalls/mod.rs#L1180-L1189 */
    fd_ed25519_point_t _r[1];
    fd_ed25519_point_t * r = multi_scalar_mul_edwards( _r, scalars, points, points_len );

    if( FD_LIKELY( r ) ) {
      /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1339-L1343 */
      fd_vm_haddr_query_t result_query = {
        .vaddr    = result_point_addr,
        .align    = FD_VM_ALIGN_RUST_POD_U8_ARRAY,
        .sz       = FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ,
        .is_slice = 0,
      };

      fd_vm_haddr_query_t * queries[] = { &result_query };
      FD_VM_TRANSLATE_MUT( vm, queries );

      fd_ed25519_point_tobytes( result_query.haddr, r );
      ret = 0UL;
    }
    break;
  }

  case FD_VM_SYSCALL_SOL_CURVE_CURVE25519_RISTRETTO: {
    fd_ristretto255_point_t _r[1];
    fd_ristretto255_point_t * r = multi_scalar_mul_ristretto( _r, scalars, points, points_len );

    if( FD_LIKELY( r ) ) {
      /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1380-L1384 */
      fd_vm_haddr_query_t result_query = {
        .vaddr    = result_point_addr,
        .align    = FD_VM_ALIGN_RUST_POD_U8_ARRAY,
        .sz       = FD_VM_SYSCALL_SOL_CURVE_CURVE25519_POINT_SZ,
        .is_slice = 0,
      };

      fd_vm_haddr_query_t * queries[] = { &result_query };
      FD_VM_TRANSLATE_MUT( vm, queries );

      fd_ristretto255_point_tobytes( result_query.haddr, r );
      ret = 0UL;
    }
    break;
  }

  default:
    /* COV: this can never happen because of the previous switch */
    return FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE; /* SyscallError::InvalidAttribute */
  }

soft_error:
  *_ret = ret;
  return FD_VM_SUCCESS;
}
