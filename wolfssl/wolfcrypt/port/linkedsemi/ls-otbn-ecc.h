#ifndef __LS_OTBN_ECC_WOLFSSL__
#define __LS_OTBN_ECC_WOLFSSL__

#if defined(WOLFSSL_ZEPHYR)
void wc_LS_Otbn_Module_Init(void);
void wc_LS_Otbn_Module_DeInit(void);
int ls_otbn_ecc_creat_key(struct ecc_key* key, int curve_id, int keySize);
int ls_otbn_ecc_sign_hash_ex(const byte* in, word32 inLen, MATH_INT_T* r, MATH_INT_T* s,
                            byte* out, word32 *outLen, struct ecc_key* key);
int ls_otbn_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
                            byte* out, word32* outlen);
int ls_otbn_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                    word32 hashlen, int* res, ecc_key* key);

#endif


#endif