#ifndef _LS_SM4_H_
#define _LS_SM4_H_

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SM4_ALT)
    #include <ls_hal_sm4.h>
    #define SM4_IV_SIZE 16
    #define SM4_BLOCK_SIZE 16
    typedef struct wc_Sm4 {
        uint8_t iv[SM4_IV_SIZE];
    } wc_Sm4;
    int wc_Sm4Init(wc_Sm4* sm4, void* heap, int devId);
    void wc_Sm4Free(wc_Sm4* sm4);
    int wc_Sm4SetKey(wc_Sm4* sm4, const byte* key, word32 len);
    int wc_Sm4SetIV(wc_Sm4* sm4, const byte* iv);
    int wc_Sm4EcbEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz);
    int wc_Sm4EcbDecrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz);
    int wc_Sm4CtrEncrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz);
#endif /* CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SM4_ALT */

#endif