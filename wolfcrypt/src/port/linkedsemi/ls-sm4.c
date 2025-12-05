#include <wolfssl/wolfcrypt/settings.h>
#include <tests/unit.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-sm4.h>
#include "ls_msp_sm4.h"
#include "field_manipulate.h"
#include "reg_sm4_type.h"

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
        __ASSERT_NO_MSG(sz % 16 == 0);

        uint32_t *input = (uint32_t *)in;
        uint32_t *output = (uint32_t *)out;

        REG_FIELD_WR(LSSM4->SM4_CTRL, SM4_CALC_LEN, (uint8_t)(sz / 16 - 1));
        REG_FIELD_WR(LSSM4->SM4_CTRL,SM4_CALC_DEC,0);

        LSSM4->SM4_START = SM4_CALC_START_MASK;

        if(REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1)
        {
            LSSM4->CALC_WRD = (*input++);
            LSSM4->CALC_WRD = (*input++);
            LSSM4->CALC_WRD = (*input++);
            LSSM4->CALC_WRD = (*input++);
            LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
        }
        do
        {
            if(REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1)
            {
                *output++ = (LSSM4->CALC_RSLT0);
                *output++ = (LSSM4->CALC_RSLT1);
                *output++ = (LSSM4->CALC_RSLT2);
                *output++ = (LSSM4->CALC_RSLT3);
                LSSM4->CALC_WRD = (*input++);
                LSSM4->CALC_WRD = (*input++);
                LSSM4->CALC_WRD = (*input++);
                LSSM4->CALC_WRD = (*input++);
                LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
            }

        } while (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_END) == 0);
        LSSM4->INTR_CLR = SM4_INTR_END_MASK;
        *output++ = (LSSM4->CALC_RSLT0);
        *output++ = (LSSM4->CALC_RSLT1);
        *output++ = (LSSM4->CALC_RSLT2);
        *output++ = (LSSM4->CALC_RSLT3);

        return 0;
    }
    int wc_Sm4EcbDecrypt(wc_Sm4* sm4, byte* out, const byte* in, word32 sz)
    {
        __ASSERT_NO_MSG(sz % 16 == 0);

        uint32_t *input = (uint32_t *)in;
        uint32_t *output = (uint32_t *)out;

        REG_FIELD_WR(LSSM4->SM4_CTRL, SM4_CALC_LEN, (uint8_t)(sz / 16 - 1));
        REG_FIELD_WR(LSSM4->SM4_CTRL,SM4_CALC_DEC,1);

        LSSM4->SM4_START = SM4_CALC_START_MASK;

        if(REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1)
        {
            LSSM4->CALC_WRD = (*input++);
            LSSM4->CALC_WRD = (*input++);
            LSSM4->CALC_WRD = (*input++);
            LSSM4->CALC_WRD = (*input++);
            LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
        }
        do
        {
            if(REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1)
            {
                *output++ = (LSSM4->CALC_RSLT0);
                *output++ = (LSSM4->CALC_RSLT1);
                *output++ = (LSSM4->CALC_RSLT2);
                *output++ = (LSSM4->CALC_RSLT3);
                LSSM4->CALC_WRD = (*input++);
                LSSM4->CALC_WRD = (*input++);
                LSSM4->CALC_WRD = (*input++);
                LSSM4->CALC_WRD = (*input++);
                LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
            }

        } while (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_END) == 0);
        LSSM4->INTR_CLR = SM4_INTR_END_MASK;
        *output++ = (LSSM4->CALC_RSLT0);
        *output++ = (LSSM4->CALC_RSLT1);
        *output++ = (LSSM4->CALC_RSLT2);
        *output++ = (LSSM4->CALC_RSLT3);

        return 0;
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
