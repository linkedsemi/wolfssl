#ifndef _LS_HASH_H_
#define _LS_HASH_H_
#include <stdlib.h>
#include <reg_sha_type.h>

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_HASH_ALT) || defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA512_ALT)
    typedef struct {
        bool start_calc_symbol;
    } LS_HASH_Context;
#endif

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_HASH_ALT)
    #include <ls_msp_sha.h>
    #include <ls_hal_sha.h>
    /* API's */
    void wc_LS_Hash_Init();
    void wc_LSSHA_SHA224_Init(LS_HASH_Context* lsCtx);
    void wc_LSSHA_SHA256_Init(LS_HASH_Context* lsCtx);
    void wc_LSSHA_SM3_Init(LS_HASH_Context* lsCtx);
    int wc_LS_Hash_Update(LS_HASH_Context* lsCtx, const uint8_t *data, uint32_t length);
    int wc_LS_Hash_Final(LS_HASH_Context* lsCtx, uint8_t *digest);
#endif /* CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_HASH_ALT */

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA512_ALT)
    #include <ls_msp_sha512.h>
    #include <ls_hal_sha512.h>
    void wc_LS_Hash_sha512_Init();
    void wc_LSSHA_SHA512_Init(LS_HASH_Context* lsCtx);
    void wc_LSSHA_SHA384_Init(LS_HASH_Context* lsCtx);
    void wc_LS_Hash_SHA512_Update(LS_HASH_Context* lsCtx, uint32_t *addr, uint32_t length);
    void wc_LS_Hash_SHA512_Final(LS_HASH_Context* lsCtx, uint8_t *digest);
#endif /* CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA512_ALT */

#endif
