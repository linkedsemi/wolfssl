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
struct current_otbn otbn_info;

#if defined(WOLFSSL_ZEPHYR)
void wc_LS_OTBN_IRQHandler(void *param)
{
    if (LSOTBN->INTR_STATE)
    {
        LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;
        k_sem_give(&otbn_info.wait_complete);

    }
}
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
    // Supports both Zephyr and bare-metal operation
#if defined(WOLFSSL_ZEPHYR)
    ls_otbn_done_callback_register(wc_LS_OTBN_IRQHandler, NULL);
    ls_otbn_module_init();

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