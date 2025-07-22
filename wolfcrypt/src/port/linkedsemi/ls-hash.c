#include <wolfssl/wolfcrypt/settings.h>
#include <tests/unit.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-hash.h>
#include <ls_hal_sha.h>
#include <stdio.h>

int fflush(FILE *stream)
{
    ARG_UNUSED(stream);
    return 0;
}

#ifdef LS_HASH

static wolfSSL_Mutex doneLock;
static LS_HASH_Context* ls_sha_ctx = NULL;

void wc_LS_Hash_Init()
{
    wc_InitMutex(&doneLock);
    HAL_LSSHA_Init();
}


void wc_LSSHA_SHA224_Init(LS_HASH_Context* lsCtx)
{
    XMEMSET(lsCtx, 0, sizeof(LS_HASH_Context));
    HAL_LSSHA_SHA224_Init();
}

void wc_LSSHA_SHA256_Init(LS_HASH_Context* lsCtx)
{
    XMEMSET(lsCtx, 0, sizeof(LS_HASH_Context));
    HAL_LSSHA_SHA256_Init();
}

void wc_LSSHA_SM3_Init(LS_HASH_Context* lsCtx)
{
    XMEMSET(lsCtx, 0, sizeof(LS_HASH_Context));
    HAL_LSSHA_SM3_Init();
}

int  wc_LS_Hash_Update(LS_HASH_Context* lsCtx, const uint8_t *data,uint32_t length)
{
    int ret = 0;
    if(!lsCtx->start_calc_symbol)
    {
        wc_LockMutex(&doneLock);
        ls_sha_ctx = lsCtx;
        lsCtx->start_calc_symbol = true;
    }
    AssertIntEQ(ls_sha_ctx,lsCtx);
    ret = HAL_LSSHA_Update(data,length);
    return ret;
}

int  wc_LS_Hash_Final(LS_HASH_Context* lsCtx, uint8_t *digest)
{
    int ret = 0;
    AssertIntEQ(ls_sha_ctx,lsCtx);
    ret = HAL_LSSHA_Final(digest);
    ls_sha_ctx = NULL;
    lsCtx->start_calc_symbol = false;
    wc_UnLockMutex(&doneLock);
    return ret;
}

#endif /* LS_HASH */