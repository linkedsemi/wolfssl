#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "reg_sysc_sec_cpu.h"
#include "field_manipulate.h"
#include "qsh.h"
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-otbn.h>
#if defined(WOLFSSL_ZEPHYR)
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include "otbn/ls_otbn_config.h"
#endif

#if defined(WOLFSSL_ZEPHYR)
void ls_otbn_module_init(void);
#endif
void HAL_LSOTBN_MSP_Init(void);
void HAL_LSOTBN_MSP_DeInit(void);
void wc_LS_Otbn_Module_Init(void)
{
#if defined(CONFIG_WOLFSSL_LINKEDSEMI_OTBN_DELEGATION_CLIENT)
    return;
#endif
    ls_otbn_module_init();
}

void wc_LS_Otbn_Module_DeInit(void)
{
    ls_otbn_module_deinit();
}


