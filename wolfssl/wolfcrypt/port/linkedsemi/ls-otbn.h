#ifndef __LS_OTBN_H__
#define __LS_OTBN_H__
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h> 
#if defined(WOLFSSL_ZEPHYR)
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#endif



struct current_otbn
{
    wolfSSL_Mutex doneLock;
#if defined(WOLFSSL_ZEPHYR)
    struct k_sem wait_complete;
#endif
};

#if defined(CONFIG_WOLFSSL_LINKEDSEMI_OTBN_DELEGATION_CLIENT)
#define CACHE_ALIGN_32 __attribute__((aligned(32)))
#else
#define CACHE_ALIGN_32
#endif

void wc_ls_otbn_cmd(enum HAL_OTBN_CMD cmd);
void wc_LS_Otbn_Module_Init(void);
void wc_LS_Otbn_Module_DeInit(void);

#endif