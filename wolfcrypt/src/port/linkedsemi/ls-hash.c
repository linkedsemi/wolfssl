#include <wolfssl/wolfcrypt/settings.h>
#include <tests/unit.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-hash.h>
#include <stdio.h>

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_HASH_ALT) || defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA512_ALT)

    int fflush(FILE *stream)
    {
        ARG_UNUSED(stream);
        return 0;
    }

    static wolfSSL_Mutex doneLock;
    static LS_HASH_Context* ls_sha_ctx = NULL;

#endif

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_HASH_ALT)
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

    int wc_LS_Hash_Update(LS_HASH_Context* lsCtx, const uint8_t *data, uint32_t length)
    {
        int ret = 0;
        if (!lsCtx->start_calc_symbol)
        {
            wc_LockMutex(&doneLock);
            ls_sha_ctx = lsCtx;
            lsCtx->start_calc_symbol = true;
        }
        AssertIntEQ(ls_sha_ctx, lsCtx);
        ret = HAL_LSSHA_Update(data, length);
        return ret;
    }

    int wc_LS_Hash_Final(LS_HASH_Context* lsCtx, uint8_t *digest)
    {
        int ret = 0;
        AssertIntEQ(ls_sha_ctx, lsCtx);
        ret = HAL_LSSHA_Final(digest);
        ls_sha_ctx = NULL;
        lsCtx->start_calc_symbol = false;
        wc_UnLockMutex(&doneLock);
        return ret;
    }
#endif /* CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_HASH_ALT */

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA512_ALT)
    #include "qsh.h"
    #include "field_manipulate.h"
    #include <zephyr/cache.h>
    #include "reg_sha512_type.h"
    #include <core_rv32.h>

    __attribute__((aligned(4))) static uint32_t buffer[0x20];
    struct k_sem sha384_sha512_sem;
    #define SHA384_SHA512_WAIT_TIMEOUT_MS 100000
    static uint32_t total_cnt;
    static uint32_t buffer_idx;
    static bool isFirst;
    static uint8_t read_reg_count;

    void LSSHA384_SHA512_IRQHandler(void)
    {
        if(LS_SHA512->INTR_STT & SHA512_INTR_CALC_END_MASK)
        {
            LS_SHA512->INTR_CLR = LS_SHA512->INTR_STT;
            LS_SHA512->INTR_MSK = 0x0;
            k_sem_give(&sha384_sha512_sem);
        }
    }

    void wc_LS_Hash_sha512_Init()
    {
        wc_InitMutex(&doneLock);
        k_sem_init(&sha384_sha512_sem, 0, 1);
        LS_SHA512->INTR_MSK = 0x0;
        LS_SHA512->INTR_CLR = SHA512_INTR_DMA_END_MASK | SHA512_INTR_CALC_END_MASK;
        IRQ_CONNECT(SHA512_IRQN, 3, LSSHA384_SHA512_IRQHandler,NULL, 0);
        irq_enable(SHA512_IRQN);
    }

    void wc_LSSHA_SHA384_Init(LS_HASH_Context* lsCtx)
    {
        XMEMSET(lsCtx, 0, sizeof(LS_HASH_Context));
        isFirst = true;
        read_reg_count = 12;
        LS_SHA512->CTRL = 0x8;
    }

    void wc_LSSHA_SHA512_Init(LS_HASH_Context *lsCtx)
    {
        XMEMSET(lsCtx, 0, sizeof(LS_HASH_Context));
        isFirst = true;
        read_reg_count = 16;
        LS_SHA512->CTRL = 0xc;
    }

    static void block_calculate(uint32_t addr, uint32_t block_number)
    {
        while ((LS_SHA512->STATUS & 0x1) != 0x1) ;
        REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_BLOCK_NUM, (block_number - 1));
        LS_SHA512->ADDR = addr;
        assert(((uint32_t)addr % 4) == 0);
        csi_dcache_clean_range((uint32_t *)addr, block_number*LS_SHA512_BLOCK_SIZE);

        LS_SHA512->INTR_MSK = SHA512_INTR_CALC_END_MASK;

        if (isFirst)
        {
            REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_INIT_CALC, 1);
            REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_START, 1);
            isFirst = false;
        }
        else
        {
            REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_INIT_CALC ,0);
            REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_START, 1);
        }

        k_sem_take(&sha384_sha512_sem,  K_MSEC(SHA384_SHA512_WAIT_TIMEOUT_MS));
    }

    void wc_LS_Hash_SHA512_Update(LS_HASH_Context* lsCtx, uint32_t *addr, uint32_t length)
    {
        if (!lsCtx->start_calc_symbol)
        {
            wc_LockMutex(&doneLock);
            ls_sha_ctx = lsCtx;
            lsCtx->start_calc_symbol = true;
        }
        AssertIntEQ(ls_sha_ctx, lsCtx);
        assert(((uint32_t)addr % 4) == 0);
        uint8_t *msg = (uint8_t *)addr;
        total_cnt += length;

        if (buffer_idx)
        {
            if ((length + buffer_idx) < LS_SHA512_BLOCK_SIZE)
            {
                memcpy(&buffer[buffer_idx], addr, length);
                buffer_idx += length;
                return;
            }
            uint32_t wr_len = LS_SHA512_BLOCK_SIZE - buffer_idx;
            memcpy(&buffer[buffer_idx], msg, wr_len);
            block_calculate((uint32_t)buffer, 1);
            buffer_idx = 0;
            length -= wr_len;
            msg += wr_len;
        }

        uint32_t block_number = length / LS_SHA512_BLOCK_SIZE;
        if (block_number)
            block_calculate((uint32_t)msg, block_number);

        if (length % LS_SHA512_BLOCK_SIZE)
        {
            memcpy(&buffer[buffer_idx], msg + (block_number * LS_SHA512_BLOCK_SIZE), length % LS_SHA512_BLOCK_SIZE);
            buffer_idx = length % LS_SHA512_BLOCK_SIZE;
        }
    }

    void wc_LS_Hash_SHA512_Final(LS_HASH_Context* lsCtx, uint8_t *digest)
    {
        AssertIntEQ(ls_sha_ctx, lsCtx);
        uint8_t *p_buffer=(uint8_t *)buffer;
        uint64_t bit_cnt = total_cnt * 8;
        p_buffer[buffer_idx++] = 0x80;
        if (buffer_idx == LS_SHA512_BLOCK_SIZE)
        {
            block_calculate((uint32_t)buffer, 1);
            buffer_idx = 0;
        }

        while (buffer_idx != (LS_SHA512_BLOCK_SIZE - 0x10))
        {
            p_buffer[buffer_idx++] = 0x0;
            if (buffer_idx == LS_SHA512_BLOCK_SIZE)
            {
                block_calculate((uint32_t)buffer, 1);
                buffer_idx = 0;
            }
        }
        memset(&p_buffer[buffer_idx], 0x0, 8);
        buffer_idx += 8;

        for (uint8_t i = 0; i < 8; i++)
        {
            p_buffer[buffer_idx + (7 - i)] = (uint8_t)(bit_cnt >> (8 * i));
        }
        buffer_idx += 8;
        block_calculate((uint32_t)buffer, 1);
        for (uint8_t j = 0; j < read_reg_count; j++)
        {
            uint32_t in = LS_SHA512->DIGEST[15 - j];
            *digest++ = in >> 24;
            *digest++ = in >> 16;
            *digest++ = in >> 8;
            *digest++ = in;
        }
        buffer_idx = 0;
        total_cnt = 0;
        ls_sha_ctx = NULL;
        lsCtx->start_calc_symbol = false;
        wc_UnLockMutex(&doneLock);
    }
#endif /* CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA512_ALT */