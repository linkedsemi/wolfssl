#ifndef _LS_HASH_H_
#define _LS_HASH_H_
#include <stdlib.h>
#include <reg_sha_type.h>
#include <leo/ls_msp_sha.h>

#ifdef LS_HASH

typedef struct {
    bool start_calc_symbol;
} LS_HASH_Context;


/* API's */
void wc_LS_Hash_Init();
void wc_LSSHA_SHA224_Init(LS_HASH_Context* lsCtx);
void wc_LSSHA_SHA256_Init(LS_HASH_Context* lsCtx);
void wc_LSSHA_SM3_Init(LS_HASH_Context* lsCtx);
int  wc_LS_Hash_Update(LS_HASH_Context* lsCtx, const uint8_t *data, uint32_t length);
int  wc_LS_Hash_Final(LS_HASH_Context* lsCtx, uint8_t *digest);

#endif /* LS_HASH */

#endif
