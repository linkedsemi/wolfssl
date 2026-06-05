#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "reg_sysc_sec_cpu.h"
#include "field_manipulate.h"
#include "platform.h"
#include "qsh.h"
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-otbn.h>
#if defined(WOLFSSL_ZEPHYR)
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#endif
struct current_otbn otbn_info;

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

#if defined(WOLFSSL_ZEPHYR)
void LS_OTBN_SYSC_IRQHandler(void);
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


    IRQ_CONNECT(OTBN_SYSC_IRQN, 3, LS_OTBN_SYSC_IRQHandler,NULL, 0);
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