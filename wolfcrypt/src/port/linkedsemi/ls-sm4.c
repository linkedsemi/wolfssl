#include <wolfssl/wolfcrypt/settings.h>
#include <tests/unit.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-sm4.h>

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SM4_ALT)
    int wc_Sm4Init(wc_Sm4* sm4, void* heap, int devId)
    {
        return HAL_SM4_Init();
    }
    int wc_Sm4SetKey(wc_Sm4* sm4, const byte* key, word32 len)
    {
        return HAL_SM4_KeyExpansion(key);
    }
    int wc_Sm4SetIV(wc_Sm4* sm4, const byte* iv)
    {
        memcpy(sm4->iv, iv, SM4_IV_SIZE);
        return 0;
    }
    int wc_Sm4EcbEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
    {
        return HAL_SM4_Encrypt(in, out, sz);
    }
    int wc_Sm4EcbDecrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
    {
        return HAL_SM4_Decrypt(in, out, sz);
    }
    void wc_Sm4Free(wc_Sm4* sm4)
    {
        HAL_SM4_DeInit();
    }
    int wc_Sm4CtrEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
    {
        HAL_SM4_CTR_Crypt(sm4->iv, in, sz, out);
        return 0;
    }
#endif
