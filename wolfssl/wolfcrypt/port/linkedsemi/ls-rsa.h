#ifndef __LS_RSA_H__
#define __LS_RSA_H__

#include "ls_otbn_rsa.h"


int ls_rsa_modexp_encrypt(const uint8_t* in, uint32_t inLen, uint8_t* out,
    uint32_t* outLen, uint8_t *exp, const uint8_t* key_n, uint32_t n_size);
int ls_rsa_modexp_decrypt(const uint8_t* in, uint32_t inLen, uint8_t* out,
    uint32_t* outLen, uint8_t *key_d, const uint8_t* key_n, uint32_t d_size);

    
#endif