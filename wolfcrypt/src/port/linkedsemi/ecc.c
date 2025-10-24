


#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h> /* for MATH_INT_T */
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "field_manipulate.h"
#include "reg_sysc_sec_cpu.h"
#include "core_rv32.h"
#include "platform.h"
#include "co_math.h"
#include "qsh.h"
#if defined(WOLFSSL_ZEPHYR)
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#endif

#include "ls_otbn_ecc.h"


struct current_otbn
{
    enum ecc_curve_ids cur_curve;
    ecc_set_type ecc_type;
    wolfSSL_Mutex doneLock;

#if defined(WOLFSSL_ZEPHYR)
    struct k_sem wait_complete;
#endif

}otbn_info;
void wc_ls_otbn_cmd(enum HAL_OTBN_CMD cmd);
int wc_ecc_get_s_covers_n(struct ecc_key* key,mp_int * s);
int wc_sm2_get_digest(struct ecc_key* key,const uint8_t *input_hash, const uint16_t hashSz, uint8_t *digest);
void xor_mult_bit(unsigned char *result, const unsigned char *a, const unsigned char *b, uint16_t num_byte);
int ls_otbn_get_key_pair(int curve_id, struct ecc_key* key, uint8_t *rnd);
int ls_trng_get_random(uint8_t *buf, uint16_t need_size);
int ls_otbn_fireware_init(struct ecc_key* key, int curve_id)
{
    uint32_t imem_size;
    uint32_t dmem_size;
    uint32_t *imem_image;
    uint32_t *dmem_image;
    // uint32_t check_sum; 
    uint32_t dmem_end;

    if(!HAL_OTBN_In_Idle_State())
    {
        //printf("The otbn is not in idle state,can not program otbn\r\n");
        return WC_HW_E;
    }

    if(otbn_info.cur_curve == curve_id)
    {
        /* no to do*/
    }else
    {
        HAL_OTBN_Checksum_Clear(); 
        otbn_info.cur_curve = curve_id;
        switch(curve_id)
        {
            case ECC_SECP256R1:
                imem_size = LS_OTBN_ECDSA_P256_IMEM_SIZE;
                dmem_size = LS_OTBN_ECDSA_P256_DMEM_SIZE;
                dmem_end = LS_OTBN_ECDSA_P256_DMEM_END;
                imem_image = (uint32_t *)p256_imem;
                dmem_image = (uint32_t *)p256_dmem;
                // check_sum = p256_checksum; 
                break;
            case ECC_SECP384R1:
                imem_size = LS_OTBN_ECDSA_P384_IMEM_SIZE;
                dmem_size = LS_OTBN_ECDSA_P384_DMEM_SIZE;
                dmem_end = LS_OTBN_ECDSA_P384_DMEM_END;
                imem_image = (uint32_t *)p384_imem;
                dmem_image = (uint32_t *)p384_dmem;
                // check_sum = p384_checksum;
                break;
            case ECC_SM2P256V1:
                imem_size = LS_OTBN_SM2_IMEM_SIZE;
                dmem_size = LS_OTBN_SM2_DMEM_SIZE;
                dmem_end = LS_OTBN_SM2_DMEM_END;
                imem_image = (uint32_t *)sm2_imem;
                dmem_image = (uint32_t *)sm2_dmem;
                // check_sum = sm2_checksum;
                break;
            default:
                return WC_HW_E;
        }
        HAL_OTBN_DMEM_Set(0, 0, dmem_end);
        HAL_OTBN_IMEM_Write(0, imem_image, imem_size);
        HAL_OTBN_DMEM_Write(0, dmem_image, dmem_size);
        // //printf("HAL_OTBN_Checksum_Get() = 0x%x\r\n",HAL_OTBN_Checksum_Get());
        // if(HAL_OTBN_Checksum_Get()!= check_sum)
        // {
        //     while(1);
        //     return WC_HW_E;
        // }
        memcpy(&otbn_info.ecc_type,key->dp,sizeof(ecc_set_type));
    }

    return 0;
}

/*
* in : input digest
* inLen : input digest length
* r : output sign parameter r
* s : output sign parameter s
* out : r addrs
* outLen: unused
* key : key info
*/
int ls_otbn_ecc_sign_hash_ex(const byte* in, word32 inLen, MATH_INT_T* r, MATH_INT_T* s,
                           byte* out, word32 *outLen, struct ecc_key* key)
{
    int err;

    uint32_t remote_random_addr;
    uint32_t remote_mode_addr;
    uint32_t mode;
    
    uint32_t remote_addr_d0;
    uint32_t remote_addr_d1;
    uint32_t remote_addr_r;
    uint32_t remote_addr_s;
    uint32_t remote_addr_msg;

    uint32_t curve;
    uint32_t curve_size;
    uint8_t random[ECC_MAXSIZE];
    uint8_t d0[ECC_MAXSIZE];
    uint8_t r_buf[ECC_MAXSIZE];
    uint8_t s_buf[ECC_MAXSIZE];
    uint8_t msg[ECC_MAXSIZE];

    //printf("ls_otbn_ecc_sign_hash_ex\r\n");
    if (in == NULL || r == NULL || s == NULL || key == NULL) {
        return ECC_BAD_ARG_E;
    }
    wc_LockMutex(&otbn_info.doneLock);

    curve = key->dp->id;
    curve_size = key->dp->size;
    memset(msg,0,ECC_MAXSIZE);
    if(curve == ECC_SM2P256V1)
    {
        wc_sm2_get_digest(key,in,inLen,msg);
        mp_reverse(msg,curve_size);
    }
    else
    {
        if(inLen >= curve_size)
        {
            inLen = curve_size;
            memcpy(msg,in,curve_size);
        }else
        {
            uint8_t offset = curve_size - inLen;
            memcpy(msg+offset,in,inLen);
        }
        mp_reverse(msg,curve_size);
    }


    err = ls_otbn_fireware_init(key,key->dp->id);
    if(err != 0)
    {
        //printf("OTBN loading error,please detect curve_id or OTBN status\r\n");
        goto exit;
    }
    switch (curve)
    {
    case ECC_SECP256R1:
        remote_mode_addr = LS_OTBN_ECDSA_P256_MODE_OFFSET;
        remote_random_addr = LS_OTBN_ECDSA_P256_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_ECDSA_P256_MODE_SIGN;
        remote_addr_d0 = LS_OTBN_ECDSA_P256_D0_OFFSET;
        remote_addr_r = LS_OTBN_ECDSA_P256_R_OFFSET;
        remote_addr_s = LS_OTBN_ECDSA_P256_S_OFFSET;
        remote_addr_msg = LS_OTBN_ECDSA_P256_MSG_OFFSET;
        remote_addr_d1 = LS_OTBN_ECDSA_P256_D1_OFFSET;
        break;
    case ECC_SECP384R1:
        remote_mode_addr = LS_OTBN_ECDSA_P384_MODE_OFFSET;
        remote_random_addr = LS_OTBN_ECDSA_P384_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_ECDSA_P384_MODE_SIGN;
        remote_addr_d0 = LS_OTBN_ECDSA_P384_D0_OFFSET;
        remote_addr_r = LS_OTBN_ECDSA_P384_R_OFFSET;
        remote_addr_s = LS_OTBN_ECDSA_P384_S_OFFSET;
        remote_addr_msg = LS_OTBN_ECDSA_P384_MSG_OFFSET;
        remote_addr_d1 = LS_OTBN_ECDSA_P384_D1_OFFSET;
        break;
    case ECC_SM2P256V1:
        remote_mode_addr = LS_OTBN_SM2_MODE_OFFSET;
        remote_random_addr = LS_OTBN_SM2_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_SM2_MODE_SIGN;
        remote_addr_d0 = LS_OTBN_SM2_D0_OFFSET;
        remote_addr_r = LS_OTBN_SM2_R_OFFSET;
        remote_addr_s = LS_OTBN_SM2_S_OFFSET;
        remote_addr_msg = LS_OTBN_SM2_MSG_OFFSET;
        remote_addr_d1 = LS_OTBN_SM2_D1_OFFSET;
        break;
    default:
        while(1);
        break;
    }

    err = ls_trng_get_random(random, ECC_MAXSIZE);
    if(err != 0)
    {
        goto exit;
    }

    if(HAL_OTBN_DMEM_Write(remote_random_addr, (uint32_t *)random, 32))
    {
        err = WC_HW_E;
        goto exit;
    }
    if(HAL_OTBN_DMEM_Write(remote_mode_addr, (uint32_t *)&mode, 4))
    {
        err = WC_HW_E;
        goto exit;
    }

    if(HAL_OTBN_DMEM_Set(remote_addr_d1,0,curve_size))
    {
        err = WC_HW_E;
        goto exit;
    }

    mp_to_unsigned_bin_len(key->k,d0,curve_size);
    mp_reverse(d0,curve_size);
    if(HAL_OTBN_DMEM_Write(remote_addr_d0, (uint32_t *)d0, curve_size))
    {
        err = WC_HW_E;
        goto exit;
    }

    if(HAL_OTBN_DMEM_Write(remote_addr_msg, (uint32_t *)msg, curve_size))
    {
        err = WC_HW_E;
        goto exit;
    }

    wc_ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        //printf("errors detected during an operation 0x%x\r\n",err);
        err = WC_HW_E;
        goto exit;
    }
    

    HAL_OTBN_DMEM_Read(remote_addr_r, (uint32_t *)r_buf, otbn_info.ecc_type.size);
    HAL_OTBN_DMEM_Read(remote_addr_s, (uint32_t *)s_buf, otbn_info.ecc_type.size);

    mp_reverse(r_buf,otbn_info.ecc_type.size);
    mp_reverse(s_buf,otbn_info.ecc_type.size);

    if(out != NULL)
    {
        memcpy(out,r_buf,otbn_info.ecc_type.size);
        memcpy(out+otbn_info.ecc_type.size,s_buf,otbn_info.ecc_type.size);
    }

    mp_read_unsigned_bin(r,r_buf,otbn_info.ecc_type.size);
    mp_read_unsigned_bin(s,s_buf,otbn_info.ecc_type.size);

exit:
    wc_UnLockMutex(&otbn_info.doneLock);
    return err;
}

int ls_otbn_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                    word32 hashlen, int* res, ecc_key* key)
{
    int err = MP_OKAY;
    
    uint32_t remote_random_addr;
    uint32_t remote_mode_addr;
    uint32_t mode;

    uint32_t remote_addr_d0;
    uint32_t remote_addr_d1;
    uint32_t remote_addr_r;
    uint32_t remote_addr_s;
    uint32_t remote_addr_msg;
    uint32_t remote_addr_qx;
    uint32_t remote_addr_qy;
    uint32_t remote_addr_r_x;

    uint32_t curve;
    uint32_t curve_size;
    // uint8_t d0[ECC_MAXSIZE];
    uint8_t buf[ECC_MAXSIZE];
    uint8_t x_r[ECC_MAXSIZE];
    uint8_t msg[ECC_MAXSIZE];
    
    *res  = 0;


    if (r == NULL || s == NULL || hash == NULL || res == NULL || key == NULL ||
            key->dp == NULL) {
        return ECC_BAD_ARG_E;
    }

    wc_LockMutex(&otbn_info.doneLock);
    
    curve_size = wc_ecc_size(key);
    curve = key->dp->id;
    memset(msg,0,curve_size);
    if(curve == ECC_SM2P256V1)
    {
        wc_sm2_get_digest(key,hash,hashlen,msg);
        mp_reverse(msg,curve_size);
    }
    else
    {
        if(hashlen >= curve_size)
        {
            hashlen = curve_size;
            memcpy(msg,hash,curve_size);
            mp_reverse(msg,curve_size);
        }else
        {
            uint8_t offset = curve_size - hashlen;
            memcpy(msg+offset,hash,hashlen);
            mp_reverse(msg,curve_size);
        }
    }

    err = ls_otbn_fireware_init(key,key->dp->id);
    if(err != 0)
    {
        //printf("OTBN loading error,please detect curve_id or OTBN status\r\n");
        goto exit;
    }

    switch (curve)
    {
    case ECC_SECP256R1:
        remote_mode_addr = LS_OTBN_ECDSA_P256_MODE_OFFSET;
        remote_random_addr = LS_OTBN_ECDSA_P256_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_ECDSA_P256_MODE_VERIFY;
        remote_addr_d0 = LS_OTBN_ECDSA_P256_D0_OFFSET;
        remote_addr_r = LS_OTBN_ECDSA_P256_R_OFFSET;
        remote_addr_s = LS_OTBN_ECDSA_P256_S_OFFSET;
        remote_addr_msg = LS_OTBN_ECDSA_P256_MSG_OFFSET;
        remote_addr_d1 = LS_OTBN_ECDSA_P256_D1_OFFSET;
        remote_addr_qx = LS_OTBN_ECDSA_P256_X_OFFSET;
        remote_addr_qy = LS_OTBN_ECDSA_P256_Y_OFFSET;
        remote_addr_r_x = LS_OTBN_ECDSA_P256_X_R_OFFSET;
        break;
    case ECC_SECP384R1:
        remote_mode_addr = LS_OTBN_ECDSA_P384_MODE_OFFSET;
        remote_random_addr = LS_OTBN_ECDSA_P384_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_ECDSA_P384_MODE_VERIFY;
        remote_addr_d0 = LS_OTBN_ECDSA_P384_D0_OFFSET;
        remote_addr_r = LS_OTBN_ECDSA_P384_R_OFFSET;
        remote_addr_s = LS_OTBN_ECDSA_P384_S_OFFSET;
        remote_addr_msg = LS_OTBN_ECDSA_P384_MSG_OFFSET;
        remote_addr_d1 = LS_OTBN_ECDSA_P384_D1_OFFSET;
        remote_addr_qx = LS_OTBN_ECDSA_P384_X_OFFSET;
        remote_addr_qy = LS_OTBN_ECDSA_P384_Y_OFFSET;
        remote_addr_r_x = LS_OTBN_ECDSA_P384_X_R_OFFSET;
        break;
    case ECC_SM2P256V1:
        remote_mode_addr = LS_OTBN_SM2_MODE_OFFSET;
        remote_random_addr = LS_OTBN_SM2_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_SM2_MODE_VERIFY;
        remote_addr_d0 = LS_OTBN_SM2_D0_OFFSET;
        remote_addr_r = LS_OTBN_SM2_R_OFFSET;
        remote_addr_s = LS_OTBN_SM2_S_OFFSET;
        remote_addr_msg = LS_OTBN_SM2_MSG_OFFSET;
        remote_addr_d1 = LS_OTBN_SM2_D1_OFFSET;
        remote_addr_qx = LS_OTBN_SM2_X_OFFSET;
        remote_addr_qy = LS_OTBN_SM2_Y_OFFSET;
        remote_addr_r_x = LS_OTBN_SM2_X_R_OFFSET;
        break;
    default:
        while(1);
        break;
    }

    if(HAL_OTBN_DMEM_Write(remote_mode_addr, (uint32_t *)&mode, 4))
    {
        //printf("errors HAL_OTBN_DMEM_Write 2 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    mp_to_unsigned_bin_len(key->pubkey.x,buf,curve_size);
    mp_reverse(buf,curve_size);
    if(HAL_OTBN_DMEM_Write(remote_addr_qx, (uint32_t *)buf, curve_size))
    {
        //printf("errors HAL_OTBN_DMEM_Write 2 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    mp_to_unsigned_bin_len(key->pubkey.y,buf,curve_size);
    mp_reverse(buf,curve_size);
    if(HAL_OTBN_DMEM_Write(remote_addr_qy, (uint32_t *)buf, curve_size))
    {
        //printf("errors HAL_OTBN_DMEM_Write 2 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    mp_to_unsigned_bin_len(r,buf,curve_size);
    mp_reverse(buf,curve_size);
    if(HAL_OTBN_DMEM_Write(remote_addr_r, (uint32_t *)buf, curve_size))
    {
        //printf("errors HAL_OTBN_DMEM_Write 2 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    mp_to_unsigned_bin_len(s,buf,curve_size);
    mp_reverse(buf,curve_size);
    if(HAL_OTBN_DMEM_Write(remote_addr_s, (uint32_t *)buf, curve_size))
    {
        //printf("errors HAL_OTBN_DMEM_Write 2 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    if(HAL_OTBN_DMEM_Write(remote_addr_msg, (uint32_t *)msg, curve_size))
    {
        //printf("errors HAL_OTBN_DMEM_Write 2 \r\n");
        err = WC_HW_E;
        goto exit;
    }


    wc_ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        //printf("errors detected during an operation 0x%x\r\n",err);
        err = WC_HW_E;
        goto exit;
    }
    
    err |= HAL_OTBN_DMEM_Read(remote_addr_r_x, (uint32_t *)x_r, curve_size);

    mp_to_unsigned_bin_len(r,buf,curve_size);
    mp_reverse(buf,curve_size);
    if(memcmp(x_r,buf,curve_size))
    {
        *res  = 0;//invalid
    }else
    {
        *res = 1;//valid
    }

    if(err)
    {
        err = WC_HW_E;
    }

exit:
    wc_UnLockMutex(&otbn_info.doneLock);
    return err;
}


int ls_otbn_ecc_creat_key(struct ecc_key* key, int curve_id, int keySize)
{
    int err = 0; 
    uint8_t buf[ECC_MAXSIZE];

    wc_LockMutex(&otbn_info.doneLock);

    if(curve_id == ECC_CURVE_DEF)
    {
        curve_id = key->dp->id;
    }
    //printf("ls_otbn_get_key_pair, curve_id = %d\r\n",curve_id);

    err = ls_otbn_fireware_init(key,curve_id);

    if(err != 0)
    {
        //printf("OTBN loading error,please detect curve_id or OTBN status\r\n");
        goto exit;
    }

    if(keySize > ECC_MAXSIZE)
    {
        //printf("keySize too big\r\n");
        err =  WC_HW_E;
        goto exit;
    }

    err = ls_trng_get_random(buf, keySize);
    if(err != 0)
    {
        //printf("RND register error\r\n");
        goto exit;
    }

    err = ls_otbn_get_key_pair(curve_id,key,buf);
    if(err != 0)
    {
        //printf("OTBN operation error\r\n");
        goto exit;
    }

    key->type = ECC_PRIVATEKEY;

exit:

    wc_UnLockMutex(&otbn_info.doneLock);
    return err;
}



int ls_otbn_get_key_pair(int curve_id, struct ecc_key* key, uint8_t *rnd)
{
    int err = 0;
    uint32_t remote_random_addr;
    uint32_t remote_mode_addr;
    uint32_t mode;

    uint32_t remote_addr_d0;
    uint32_t remote_addr_x;
    uint32_t remote_addr_y;
    uint8_t private_key[ECC_MAXSIZE];
    uint8_t public_x[ECC_MAXSIZE];
    uint8_t public_y[ECC_MAXSIZE];

    switch (curve_id)
    {
    case ECC_SECP256R1:
        remote_mode_addr = LS_OTBN_ECDSA_P256_MODE_OFFSET;
        remote_random_addr = LS_OTBN_ECDSA_P256_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_ECDSA_P256_MODE_KEYGEN;
        remote_addr_d0 = LS_OTBN_ECDSA_P256_D0_OFFSET;
        remote_addr_x = LS_OTBN_ECDSA_P256_X_OFFSET;
        remote_addr_y = LS_OTBN_ECDSA_P256_Y_OFFSET;
        break;
    case ECC_SECP384R1:
        remote_mode_addr = LS_OTBN_ECDSA_P384_MODE_OFFSET;
        remote_random_addr = LS_OTBN_ECDSA_P384_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_ECDSA_P384_MODE_KEYGEN;
        remote_addr_d0 = LS_OTBN_ECDSA_P384_D0_OFFSET;
        remote_addr_x = LS_OTBN_ECDSA_P384_X_OFFSET;
        remote_addr_y = LS_OTBN_ECDSA_P384_Y_OFFSET;
        break;
    case ECC_SM2P256V1:
        remote_mode_addr = LS_OTBN_SM2_MODE_OFFSET;
        remote_random_addr = LS_OTBN_SM2_RANDOM_SEED_OFFSET;
        mode = LS_OTBN_SM2_MODE_KEYGEN;
        remote_addr_d0 = LS_OTBN_SM2_D0_OFFSET;
        remote_addr_x = LS_OTBN_SM2_X_OFFSET;
        remote_addr_y = LS_OTBN_SM2_Y_OFFSET;
        break;
    default:
        while(1);
        break;
    }
    if(HAL_OTBN_DMEM_Write(remote_random_addr, (uint32_t *)rnd, 32))
    {
        //printf("errors HAL_OTBN_DMEM_Write  8\r\n");
        return WC_HW_E;
    }
    if(HAL_OTBN_DMEM_Write(remote_mode_addr, &mode, 4))
    {
        //printf("errors HAL_OTBN_DMEM_Write  9 \r\n");
        return WC_HW_E;
    }

    wc_ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        //printf("errors detected during an operation 0x%x",err);
        return WC_HW_E;
    }
    

    HAL_OTBN_DMEM_Read(remote_addr_d0, (uint32_t *)private_key, key->dp->size);
    HAL_OTBN_DMEM_Read(remote_addr_x, (uint32_t *)public_x, key->dp->size);
    HAL_OTBN_DMEM_Read(remote_addr_y, (uint32_t *)public_y, key->dp->size);


    mp_reverse(private_key,otbn_info.ecc_type.size);
    mp_reverse(public_x,otbn_info.ecc_type.size);
    mp_reverse(public_y,otbn_info.ecc_type.size);

    mp_read_unsigned_bin(key->k,private_key,otbn_info.ecc_type.size);
    mp_read_unsigned_bin(key->pubkey.x,public_x,otbn_info.ecc_type.size);
    mp_read_unsigned_bin(key->pubkey.y,public_y,otbn_info.ecc_type.size);
    
    // key->pubkey.z->used = 1;
    err = mp_set(key->pubkey.z, 1);
    key->type = ECC_PRIVATEKEY;

    return err;
}


int ls_otbn_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
    byte* out, word32* outlen)
{
    int err;
    uint32_t remote_mode_addr;
    uint32_t mode;

    uint32_t remote_addr_d0;
    uint32_t remote_addr_d1;
    uint32_t remote_addr_x;
    uint32_t remote_addr_y;
    uint32_t remote_addr_ok;
    
    uint32_t curve;
    uint32_t curve_size;
    // uint8_t random[ECC_MAXSIZE];
    uint8_t d0[ECC_MAXSIZE];
    // uint8_t priv_key[ECC_MAXSIZE];
    uint8_t pub_key_x[ECC_MAXSIZE];
    uint8_t pub_key_y[ECC_MAXSIZE];
    uint32_t is_ok;


    if(private_key == NULL || public_key == NULL || (private_key->dp->id != public_key->dp->id)
        || out == NULL ||  outlen == NULL)
    {
        //printf("input key id error");
        return ECC_BAD_ARG_E;
    }
    wc_LockMutex(&otbn_info.doneLock);

    err = ls_otbn_fireware_init(private_key,private_key->dp->id);
    if(err != 0)
    {
        //printf("OTBN loading error,please detect curve_id or OTBN status\r\n");
        goto exit;
    }
    curve = private_key->dp->id;
    curve_size = private_key->dp->size;

    switch (curve)
    {
    case ECC_SECP256R1:
        remote_mode_addr = LS_OTBN_ECDSA_P256_MODE_OFFSET;
        mode = LS_OTBN_ECDSA_P256_MODE_SHARED_KEY;
        remote_addr_d0 = LS_OTBN_ECDSA_P256_D0_OFFSET;
        remote_addr_d1 = LS_OTBN_ECDSA_P256_D1_OFFSET;
        remote_addr_x = LS_OTBN_ECDSA_P256_X_OFFSET;
        remote_addr_y = LS_OTBN_ECDSA_P256_Y_OFFSET;
        remote_addr_ok = LS_OTBN_ECDSA_P256_OK;
        break;
    case ECC_SECP384R1:
        remote_mode_addr = LS_OTBN_ECDSA_P384_MODE_OFFSET;
        mode = LS_OTBN_ECDSA_P384_MODE_SHARED_KEY;
        remote_addr_d0 = LS_OTBN_ECDSA_P384_D0_OFFSET;
        remote_addr_d1 = LS_OTBN_ECDSA_P384_D1_OFFSET;
        remote_addr_x = LS_OTBN_ECDSA_P384_X_OFFSET;
        remote_addr_y = LS_OTBN_ECDSA_P384_Y_OFFSET;
        remote_addr_ok = 0;/*not have*/
        break;
    case ECC_SM2P256V1:
        remote_mode_addr = LS_OTBN_SM2_MODE_OFFSET;
        mode = LS_OTBN_SM2_MODE_SHARED_KEY;
        remote_addr_d0 = LS_OTBN_SM2_D0_OFFSET;
        remote_addr_d1 = LS_OTBN_SM2_D1_OFFSET;
        remote_addr_x = LS_OTBN_SM2_X_OFFSET;
        remote_addr_y = LS_OTBN_SM2_Y_OFFSET;
        remote_addr_ok = LS_OTBN_SM2_OK;
        break;
    default:
        while(1);
        break;
    }


    if(HAL_OTBN_DMEM_Write(remote_mode_addr, (uint32_t *)&mode, 4))
    {
        //printf("errors HAL_OTBN_DMEM_Write 2 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    HAL_OTBN_DMEM_Set(remote_addr_d1,0,curve_size);

    mp_to_unsigned_bin_len(private_key->k,d0,curve_size);
    mp_reverse(d0,curve_size);
    if(HAL_OTBN_DMEM_Write(remote_addr_d0, (uint32_t *)d0, curve_size))
    {
        //printf("errors HAL_OTBN_DMEM_Write 4 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    mp_to_unsigned_bin_len(public_key->pubkey.x,pub_key_x,curve_size);
    mp_reverse(pub_key_x,curve_size);
    if(HAL_OTBN_DMEM_Write(remote_addr_x, (uint32_t *)pub_key_x, curve_size))
    {
        //printf("errors HAL_OTBN_DMEM_Write 4 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    mp_to_unsigned_bin_len(public_key->pubkey.y,pub_key_y,curve_size);
    mp_reverse(pub_key_y,curve_size);
    if(HAL_OTBN_DMEM_Write(remote_addr_y, (uint32_t *)pub_key_y, curve_size))
    {
        //printf("errors HAL_OTBN_DMEM_Write 4 \r\n");
        err = WC_HW_E;
        goto exit;
    }

    wc_ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        //printf("errors detected during an operation 0x%x\r\n",err);
        err = WC_HW_E;
        goto exit;
    }

    if(curve  != ECC_SECP384R1)
    {
        err |= HAL_OTBN_DMEM_Read(remote_addr_ok, (uint32_t *)&is_ok, 4);
        if(err == 0 && is_ok == LS_OTBN_FALSE)
        {
            //printf("inpiut public key is not on curve");
            return PUBLIC_KEY_E;
        }
    }

    err |= HAL_OTBN_DMEM_Read(remote_addr_x, (uint32_t *)pub_key_x, otbn_info.ecc_type.size);
    err |= HAL_OTBN_DMEM_Read(remote_addr_y, (uint32_t *)pub_key_y, otbn_info.ecc_type.size);

    mp_reverse(pub_key_x,otbn_info.ecc_type.size);
    mp_reverse(pub_key_y,otbn_info.ecc_type.size);

    xor_mult_bit(out,pub_key_x,pub_key_y,otbn_info.ecc_type.size);
    *outlen = otbn_info.ecc_type.size;

exit:
    wc_UnLockMutex(&otbn_info.doneLock);
    return err;
}

void xor_mult_bit(unsigned char *result, const unsigned char *a, const unsigned char *b, uint16_t num_byte) {
    for (int i = 0; i < num_byte; i++) {
        result[i] = a[i] ^ b[i];
    }
}
#if defined(WOLFSSL_ZEPHYR)
void wc_LS_OTBN_IRQHandler()
{
    if (LSOTBN->INTR_STATE)
    {
        LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;
        k_sem_give(&otbn_info.wait_complete);

    }
}
#endif

extern void HAL_OTBN_SYSC_IRQHandler(void);
extern void HAL_LSOTBN_MSP_Init(void);
extern void HAL_LSOTBN_MSP_DeInit(void);
void wc_LS_Otbn_Module_Init(void)
{
    // Supports both Zephyr and bare-metal operation
#if defined(WOLFSSL_ZEPHYR)
    uint32_t EDN_URND_BUS_IN = 0;
    REG_FIELD_WR(SYSC_SEC_CPU->INTR_CTRL_INTR_MSK, SYSC_SEC_CPU_I_EDN_URND_REQ, 0);
    SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_OTBN_MASK;
    SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_CLR_OTBN_MASK;
    SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_SET_OTBN_MASK;
    SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_SET_OTBN_MASK;
    for (uint8_t i = 0; i < 16; i++)
    {
        while (!REG_FIELD_RD(SYSC_SEC_CPU->OTBN_INTR_RAW, SYSC_SEC_CPU_I_EDN_URND_REQ)) ;
        SYSC_SEC_CPU->EDN_URND_BUS = ++EDN_URND_BUS_IN;
        REG_FIELD_WR(SYSC_SEC_CPU->OTBN_CTRL2, SYSC_SEC_CPU_EDN_URND_ACK, 1);
        REG_FIELD_WR(SYSC_SEC_CPU->OTBN_CTRL2, SYSC_SEC_CPU_EDN_URND_ACK, 0);
        SYSC_SEC_CPU->INTR_CLR_MSK = SYSC_SEC_CPU_I_EDN_URND_REQ_MASK;
    }
    SYSC_SEC_CPU->INTR_CLR_MSK = FIELD_BUILD(SYSC_SEC_CPU_I_EDN_RND_REQ, 1) |
                            FIELD_BUILD(SYSC_SEC_CPU_I_EDN_URND_REQ, 1) |
                            FIELD_BUILD(SYSC_SEC_CPU_I_OTBN_OTP_REQ, 1);
    SYSC_SEC_CPU->INTR_CTRL_INTR_MSK = FIELD_BUILD(SYSC_SEC_CPU_I_EDN_RND_REQ, 1) |
                              FIELD_BUILD(SYSC_SEC_CPU_I_EDN_URND_REQ, 1) |
                              FIELD_BUILD(SYSC_SEC_CPU_I_OTBN_OTP_REQ, 1);


    IRQ_CONNECT(OTBN_SYSC_IRQN, 3, HAL_OTBN_SYSC_IRQHandler,NULL, 0);
    irq_enable(OTBN_SYSC_IRQN);
    IRQ_CONNECT(OBTN_IRQN, 3, wc_LS_OTBN_IRQHandler,NULL, 0);
    irq_enable(OBTN_IRQN);

    k_sem_init(&otbn_info.wait_complete,0,1);
#else
    HAL_LSOTBN_MSP_Init();
#endif
    wc_InitMutex(&otbn_info.doneLock);

}

void wc_LS_Otbn_Module_DeInit(void)
{
    HAL_LSOTBN_MSP_DeInit();
}

void wc_ls_otbn_cmd(enum HAL_OTBN_CMD cmd)
{
#if defined(WOLFSSL_ZEPHYR)
    if (LSOTBN->INTR_STATE)
        LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;
    LSOTBN->INTR_ENABLE = OTBN_INTR_ENABLE_EN_MASK;
    LSOTBN->CMD = cmd;
    (void)k_sem_take(&otbn_info.wait_complete, K_FOREVER);
#else
    HAL_OTBN_CMD_Write_Polling(cmd);
#endif

}