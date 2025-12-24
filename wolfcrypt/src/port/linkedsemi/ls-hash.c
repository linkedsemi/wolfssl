#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-hash.h>
#include <stdio.h>

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA224_SHA256_SM3_ALT) || defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA384_SHA512_ALT)
    #include "qsh.h"
    static wolfSSL_Mutex doneLock;
    static LS_HASH_Context* ls_sha_ctx = NULL;

#endif

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA224_SHA256_SM3_ALT)
    struct k_sem dma_sem;
    struct k_sem sha224_sha256_sm3_sem;
    void LSSHA224_SHA256_SM3_IRQHandler(void)
    {
        if(LSSHA->INTR_S & SHA_FSM_END_INTR_MASK)
        {
            LSSHA->INTR_C = LSSHA->INTR_S;
            LSSHA->INTR_M = 0;
            k_sem_give(&sha224_sha256_sm3_sem);
        }
    }

    void wc_LS_Hash_Init()
    {
        wc_InitMutex(&doneLock);
        k_sem_init(&dma_sem, 0, 1);
        k_sem_init(&sha224_sha256_sm3_sem, 0, 1);
        LSSHA->INTR_M = 0;
        LSSHA->INTR_C = SHA_FSM_END_INTR_MASK | SHA_FSM_EMPT_INTR_MASK;
        IRQ_CONNECT(CALC_SHA_IRQN, 3, LSSHA224_SHA256_SM3_IRQHandler, NULL, 0);
        irq_enable(CALC_SHA_IRQN);
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
        __ASSERT_NO_MSG(ls_sha_ctx == lsCtx);
        ret = HAL_LSSHA_Update(data, length);
        return ret;
    }

    int wc_LS_Hash_Final(LS_HASH_Context* lsCtx, uint8_t *digest)
    {
        int ret = 0;
        __ASSERT_NO_MSG(ls_sha_ctx == lsCtx);
        ret = HAL_LSSHA_Final(digest);
        ls_sha_ctx = NULL;
        lsCtx->start_calc_symbol = false;
        wc_UnLockMutex(&doneLock);
        return ret;
    }
#endif /* CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA224_SHA256_SM3_ALT */

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA224_SHA256_SM3_ALT) && defined(CONFIG_DMA)
    #include <zephyr/drivers/dma.h>
    #include <zephyr/drivers/dma/dma_dw.h>
    #include <soc_dma.h>
    #include "dmac_config.h"
    #include "field_manipulate.h"
    #include "reg_sha_type.h"
    #include "platform.h"
    #include <zephyr/cache.h>

    // #define CONFIG_SHA224_SHA256_SM3_DMA1
    #define CONFIG_SHA224_SHA256_SM3_DMA_CHANNEL 7

    #if defined(CONFIG_SHA224_SHA256_SM3_DMA1)
    #define dmac DEVICE_DT_GET(DT_NODELABEL(dmac1))
    #else
    #define dmac DEVICE_DT_GET(DT_NODELABEL(dmac2))
    #endif

    #define SHA_BLOCK_SIZE 64
    #define SHA224_SHA256_SM3_DMA_WAIT_TIMEOUT_MS 100000
    #define SHA224_SHA256_SM3_DMA_MAX_BLOCK_SIZE (2047*4/SHA_BLOCK_SIZE)
    #define SHA224_SHA256_SM3_DMA_MAX_BYTES      (SHA224_SHA256_SM3_DMA_MAX_BLOCK_SIZE * SHA_BLOCK_SIZE)
    #define SHA_PADDING_MOD 56

    static uint32_t current_word;
    static uint8_t current_block_bytes;
    static uint64_t total_length;

    static void sha_variable_init()
    {
        total_length = 0;
        current_block_bytes = 0;
        current_word = 0;
    }

    int LSSHA_SHA256_Init()
    {
        LSSHA->SHA_CTRL = FIELD_BUILD(SHA_FST_DAT,1)|FIELD_BUILD(SHA_CALC_SHA224,0)|FIELD_BUILD(SHA_CALC_SM3,0);
        sha_variable_init();
        return HAL_OK;
    }

    int LSSHA_SHA224_Init()
    {
        LSSHA->SHA_CTRL = FIELD_BUILD(SHA_FST_DAT,1)|FIELD_BUILD(SHA_CALC_SHA224,1)|FIELD_BUILD(SHA_CALC_SM3,0);
        sha_variable_init();
        return HAL_OK;
    }

    int LSSHA_SM3_Init()
    {
        LSSHA->SHA_CTRL = FIELD_BUILD(SHA_FST_DAT,1)|FIELD_BUILD(SHA_CALC_SHA224,0)|FIELD_BUILD(SHA_CALC_SM3,1);
        sha_variable_init();
        return HAL_OK;
    }

    static void byte_update(const uint8_t val)
    {
        switch(current_block_bytes%sizeof(uint32_t))
        {
        case 0:
            MODIFY_REG(current_word,0xff,val);
        break;
        case 1:
            MODIFY_REG(current_word,0xff00,val<<8);
        break;
        case 2:
            MODIFY_REG(current_word,0xff0000,val<<16);
        break;
        case 3:
            MODIFY_REG(current_word,0xff000000,val<<24);
        break;
        }
        current_block_bytes++;
        if(current_block_bytes%sizeof(uint32_t)==0)
        {
            LSSHA->FIFO_DAT = current_word;
        }
    }

    static void sha_start(bool end)
    {
        if(current_block_bytes==SHA_BLOCK_SIZE)
        {
            current_block_bytes = 0;
            while((LSSHA->INTR_R&SHA_FSM_END_INTR_MASK)==0);
            LSSHA->INTR_C = SHA_FSM_END_INTR_MASK;
            if(!end)    LSSHA->SHA_START = 1;
        }
    }

    int LSSHA_Final(uint8_t *digest)
    {
        if(!current_block_bytes)
        {
            LSSHA->DMA_CTRL = 0;
            REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, 0);
            LSSHA->SHA_START = 1;
        }
        byte_update(0x80);
        while(current_block_bytes!=SHA_PADDING_MOD)
        {
            sha_start(false);
            byte_update(0x00);
        }
        byte_update(total_length>>56);
        byte_update(total_length>>48);
        byte_update(total_length>>40);
        byte_update(total_length>>32);
        byte_update(total_length>>24);
        byte_update(total_length>>16);
        byte_update(total_length>>8);
        byte_update(total_length>>0);
        sha_start(true);
        uint8_t i;
        uint8_t count = REG_FIELD_RD(LSSHA->SHA_CTRL,SHA_CALC_SHA224) != 1 ? SHA256_WORDS_NUM : SHA224_WORDS_NUM;
        for (i = 0; i < count; ++i)
        {
            uint32_t val = LSSHA->SHA_RSLT[i];
            *digest++ = val>>24;
            *digest++ = val>>16;
            *digest++ = val>>8;
            *digest++ = val;
        }
        return 0;
    }

    static void sha224_sha256_sm3_dma_callback(const struct device *dev, void *user_data,
                    uint32_t channel, int status)
    {
        if (status == DMA_STATUS_COMPLETE || status < 0) {
            k_sem_give(&dma_sem);
        }
    }

    static void dma_conf(uint32_t source_address, uint32_t dest_address, size_t ilen)
    {
        uint32_t blk_cnt = ilen >> 2;
        uint8_t ret;
        struct dma_config dma_cfg;
        struct dma_block_config blk;
        blk.block_size = blk_cnt;
        blk.source_address  = source_address;
        blk.dest_address    = dest_address;
        blk.source_addr_adj = DMA_ADDR_ADJ_INCREMENT;
        blk.dest_addr_adj   = DMA_ADDR_ADJ_NO_CHANGE;
        blk.next_block      = NULL;
        /* Config DMA Config */
        memset(&dma_cfg, 0, sizeof(dma_cfg));
        dma_cfg.dma_slot            = DMA_SHA256;
        dma_cfg.channel_direction   = MEMORY_TO_PERIPHERAL;
        dma_cfg.complete_callback_en= 0;
        dma_cfg.channel_priority    = 0;
        dma_cfg.source_data_size    = 4;
        dma_cfg.dest_data_size      = 4;
        dma_cfg.source_burst_length = 8;
        dma_cfg.dest_burst_length   = 8;
        dma_cfg.block_count         = 1;
        dma_cfg.head_block          = &blk;
        dma_cfg.user_data           = NULL;
        dma_cfg.dma_callback        = sha224_sha256_sm3_dma_callback;

        ret = dma_config(dmac, CONFIG_SHA224_SHA256_SM3_DMA_CHANNEL, &dma_cfg);
        if (ret < 0) {
            printk("dma_config failed %d", ret);
        }
        ret = dma_start(dmac, CONFIG_SHA224_SHA256_SM3_DMA_CHANNEL);
        if (ret < 0) {
            printk("dma_start failed %d", ret);
        }
    }

    void wc_LSSHA_SHA224_Init_dma(LS_HASH_Context* lsCtx)
    {
        XMEMSET(lsCtx, 0, sizeof(LS_HASH_Context));
        LSSHA_SHA224_Init();
    }

    void wc_LSSHA_SHA256_Init_dma(LS_HASH_Context* lsCtx)
    {
        XMEMSET(lsCtx, 0, sizeof(LS_HASH_Context));
        LSSHA_SHA256_Init();
    }

    void wc_LSSHA_SM3_Init_dma(LS_HASH_Context* lsCtx)
    {
        XMEMSET(lsCtx, 0, sizeof(LS_HASH_Context));
        LSSHA_SM3_Init();
    }

    int wc_LS_Hash_Update_dma(LS_HASH_Context* lsCtx, const uint8_t *input, uint32_t ilen)
    {
        if (!lsCtx->start_calc_symbol)
        {
            wc_LockMutex(&doneLock);
            ls_sha_ctx = lsCtx;
            lsCtx->start_calc_symbol = true;
        }
        __ASSERT_NO_MSG(ls_sha_ctx == lsCtx);

        uint32_t trans_count = ilen / SHA224_SHA256_SM3_DMA_MAX_BYTES;
        uint32_t dma_calc_bytes;
        uint32_t remain_len = 0;

        const unsigned char *dma_start_input = NULL;
        const unsigned char *remain_input = NULL;

        total_length += ilen*8;

        for(uint32_t i=0; i <= trans_count; i++)
        {
            if(trans_count == 0){
                REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, ilen/SHA_BLOCK_SIZE - 1);
                dma_calc_bytes = (ilen/SHA_BLOCK_SIZE)*SHA_BLOCK_SIZE;
                remain_len = ilen - dma_calc_bytes;
                dma_start_input = input;
                remain_input = input + dma_calc_bytes;
            }
            else if((i == trans_count) && (trans_count > 0)){
                dma_calc_bytes = ((ilen - SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count)/SHA_BLOCK_SIZE)*SHA_BLOCK_SIZE;
                if(dma_calc_bytes < SHA_BLOCK_SIZE)
                {
                    remain_len = ilen - SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count;
                    remain_input = input + SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count;
                }else{
                    REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, dma_calc_bytes/SHA_BLOCK_SIZE - 1);
                    remain_len = ilen - (SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count) - dma_calc_bytes;
                    dma_start_input = input + SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count;
                    remain_input = dma_start_input + dma_calc_bytes;
                }
            }
            else{
                REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, SHA224_SHA256_SM3_DMA_MAX_BLOCK_SIZE-1);
                dma_calc_bytes = SHA224_SHA256_SM3_DMA_MAX_BYTES;
                dma_start_input = input + SHA224_SHA256_SM3_DMA_MAX_BYTES * i;
            }

            if(dma_calc_bytes >= SHA_BLOCK_SIZE)
            {
                LSSHA->INTR_C = 3;
                LSSHA->INTR_M = SHA_FSM_END_INTR_MASK;
                LSSHA->SHA_START = 1;
                LSSHA->SHA_CTRL &= ~SHA_FST_DAT_MASK;
                sys_cache_data_flush_range((void *)dma_start_input, dma_calc_bytes);
                LSSHA->DMA_CTRL = 1;
                dma_conf((uint32_t)dma_start_input, SEC_CALC_SHA_ADDR + 0x30, dma_calc_bytes);
                k_sem_take(&dma_sem,  K_MSEC(SHA224_SHA256_SM3_DMA_WAIT_TIMEOUT_MS));
                k_sem_take(&sha224_sha256_sm3_sem,  K_MSEC(SHA224_SHA256_SM3_DMA_WAIT_TIMEOUT_MS));
            }
        }

        if(remain_len)
        {
            LSSHA->DMA_CTRL = 0;
            REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, 0);
            LSSHA->SHA_START = 1;
            LSSHA->SHA_CTRL &= ~SHA_FST_DAT_MASK;
            do{
                byte_update(*remain_input);
                remain_input++;
                remain_len--;
            }while(current_block_bytes!=SHA_BLOCK_SIZE&&remain_len);
        }
        return 0;
    }

    int wc_LS_Hash_Final_dma(LS_HASH_Context* lsCtx, uint8_t *output)
    {
        int ret = 0;
        __ASSERT_NO_MSG(ls_sha_ctx == lsCtx);
        ret = LSSHA_Final(output);
        ls_sha_ctx = NULL;
        lsCtx->start_calc_symbol = false;
        wc_UnLockMutex(&doneLock);
        return ret;
    }
#endif /*CONFIG_MBEDTLS_SHA224_SHA256_SM3_LINKEDSEMI_HARDWARE_ALT && CONFIG_DMA */

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA384_SHA512_ALT)
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
        __ASSERT_NO_MSG(((uint32_t)addr % 4) == 0);
        csi_dcache_clean_range((uint32_t *)addr, block_number*LS_SHA512_BLOCK_SIZE);

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

        LS_SHA512->INTR_MSK = SHA512_INTR_CALC_END_MASK;

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
        __ASSERT_NO_MSG(ls_sha_ctx == lsCtx);
        __ASSERT_NO_MSG(((uint32_t)addr % 4) == 0);
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
        __ASSERT_NO_MSG(ls_sha_ctx == lsCtx);
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
#endif /* CONFIG_WOLFSSL_LINKEDSEMI_HARDWARE_SHA384_SHA512_ALT */