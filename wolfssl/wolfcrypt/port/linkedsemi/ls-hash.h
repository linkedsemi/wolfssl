#ifndef _LS_HASH_H_
#define _LS_HASH_H_
#include <stdlib.h>
#include <reg_sha_type.h>

#if defined(LS_HASH) || defined(LS_HASH_SHA512)
    typedef struct {
        bool start_calc_symbol;
    } LS_HASH_Context;
#endif

#if defined(LS_HASH) && defined(CONFIG_SOC_LS1010)
    #include <ls_msp_sha.h>
    #include <ls_hal_sha.h>
    /* API's */
    void wc_LS_Hash_Init();
    void wc_LSSHA_SHA224_Init(LS_HASH_Context* lsCtx);
    void wc_LSSHA_SHA256_Init(LS_HASH_Context* lsCtx);
    void wc_LSSHA_SM3_Init(LS_HASH_Context* lsCtx);
    int wc_LS_Hash_Update(LS_HASH_Context* lsCtx, const uint8_t *data, uint32_t length);
    int wc_LS_Hash_Final(LS_HASH_Context* lsCtx, uint8_t *digest);
#endif /* LS_HASH */

#if defined(LS_HASH_SHA512) && defined(CONFIG_SOC_LSQSH)
    #include <ls_msp_sha512.h>
    #include <ls_hal_sha512.h>
    void wc_LS_Hash_sha512_Init();
    void wc_LSSHA_SHA512_Init(LS_HASH_Context* lsCtx);
    void wc_LSSHA_SHA384_Init(LS_HASH_Context* lsCtx);
    void wc_LS_Hash_SHA512_Update(LS_HASH_Context* lsCtx, uint32_t *addr, uint32_t length);
    void wc_LS_Hash_SHA512_Final(LS_HASH_Context* lsCtx, uint8_t *digest);
#endif /* LS_HASH_SHA512 */

#endif
