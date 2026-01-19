#ifndef CONFIG_WOLFSSL_LINKEDSEMI_OTBN_DELEGATION_CLIENT
#include "reg_otbn_type.h"
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-otbn.h>
#include <wolfssl/wolfcrypt/port/linkedsemi/ls-rsa.h>
enum {
  /**
   * Common RSA exponent with a specialized implementation.
   *
   * This exponent is 2^16 + 1, and called "F4" because it's the fourth Fermat
   * number.
   */
  kExponentF4 = 65537,
};

static int load_rsa_modexp_app(void) {
  // Load the OTBN app. Fails if OTBN is not idle.
    if((LSOTBN->STATUS != 0))
        return -1;
    
    HAL_OTBN_IMEM_Write(0, (uint32_t *)rsa_imem, RSA_IMEM_SIZE);
    // HAL_OTBN_DMEM_Write(0, rsa_dmem, RSA_DMEM_SIZE);

    return 0;
}

static int rsa_modexp_wait(size_t *num_words) {
  // Spin here waiting for OTBN to complete.
  // while (!LSOTBN->INTR_STATE);
  // Clear the interrupt flag.
  // LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;

  // Read the application mode.
  uint32_t mode;
  HAL_OTBN_DMEM_Read(RSA_OFFSET_MODE, &mode, sizeof(mode));

  *num_words = 0;
  if (mode == MODE_RSA_2048_MODEXP || mode == MODE_RSA_2048_MODEXP_F4) {
    *num_words = kRsa2048NumWords;
  } else if (mode == MODE_RSA_3072_MODEXP || mode == MODE_RSA_3072_MODEXP_F4) {
    *num_words = kRsa3072NumWords;
  } else if (mode == MODE_RSA_4096_MODEXP || mode == MODE_RSA_4096_MODEXP_F4) {
    *num_words = kRsa4096NumWords;
  } else {
    // Unrecognized mode.
    return -1;
  }

  return 0;
}

/**
 * Finalizes a modular exponentiation of variable size.
 *
 * Blocks until OTBN is done, checks for errors. Ensures the mode matches
 * expectations. Reads back the result, and then performs an OTBN secure wipe.
 *
 * @param num_words Number of words for the modexp result.
 * @param[out] result Result of the modexp operation.
 * @return Status of the operation (OK or error).
 */
static int rsa_modexp_finalize(const size_t num_words, uint32_t *result) {
  // Wait for OTBN to complete and get the result size.
  size_t num_words_inferred;
  rsa_modexp_wait(&num_words_inferred);

  // Check that the inferred result size matches expectations.
  if (num_words != num_words_inferred) {
    return -1;
  }

  // Read the result.
  HAL_OTBN_DMEM_Read(RSA_OFFSET_INOUT, result, num_words*4);

  // Wipe DMEM.
  return 0;
}

int ls_rsa_modexp_encrypt(const uint8_t* in, uint32_t inLen, uint8_t* out,
    uint32_t* outLen, uint8_t *exp, const uint8_t* key_n, uint32_t n_size)
{
  int err = 0;
  uint32_t mode;
  uint32_t num_bytes = n_size / 8;
  uint32_t rsa_exp = exp[0] | (exp[1] << 8) | (exp[2] << 16) | (exp[3] << 24);
  if(rsa_exp != kExponentF4)
  {
    switch (n_size)
    {
      case 2048:
        mode = MODE_RSA_2048_MODEXP;
        break;
      case 3072:
        mode = MODE_RSA_3072_MODEXP;
        break;
      case 4096:
        mode = MODE_RSA_4096_MODEXP;
        break;
      default:
        while(1);
        break;
    }
  }else
  {
    switch (n_size)
    {
      case 2048:
        mode = MODE_RSA_2048_MODEXP_F4;
        break;
      case 3072:
        mode = MODE_RSA_3072_MODEXP_F4;
        break;
      case 4096:
        mode = MODE_RSA_4096_MODEXP_F4;
        break;
      default:
        while(1);
        break;
    }
  }
  // Load the OTBN app. Fails if OTBN is not idle.
  load_rsa_modexp_app();

  HAL_OTBN_DMEM_Write(RSA_OFFSET_MODE, (uint32_t *)&mode, sizeof(mode));

  if(rsa_exp != kExponentF4)
  {
      HAL_OTBN_DMEM_Write(RSA_OFFSET_D, (uint32_t *)exp, num_bytes);
  }

  // Set the base and the modulus n.
  HAL_OTBN_DMEM_Write(RSA_OFFSET_INOUT, (uint32_t *)in, num_bytes);
  HAL_OTBN_DMEM_Write(RSA_OFFSET_N, (uint32_t *)key_n, num_bytes);

  // Start OTBN.
  wc_ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);
  err = HAL_OTBN_Error_Bit_Get();
  if(err)
  {
      //printf("errors detected during an operation 0x%x",err);
      return WC_HW_E;
  }
    
  rsa_modexp_finalize(num_bytes/4, (uint32_t *)out);
  *outLen = num_bytes;

  return 0;
}

int ls_rsa_modexp_decrypt(const uint8_t* in, uint32_t inLen, uint8_t* out,
    uint32_t* outLen, uint8_t *key_d, const uint8_t* key_n, uint32_t d_size)
{
  int err = 0;
  uint32_t mode;
  uint32_t num_bytes = d_size / 8;

  switch (d_size)
  {
    case 2048:
      mode = MODE_RSA_2048_MODEXP;
      break;
    case 3072:
      mode = MODE_RSA_3072_MODEXP;
      break;
    case 4096:
      mode = MODE_RSA_4096_MODEXP;
      break;
    default:
      while(1);
      break;
  }

  // Load the OTBN app. Fails if OTBN is not idle.
  load_rsa_modexp_app();

  HAL_OTBN_DMEM_Write(RSA_OFFSET_MODE, (uint32_t *)&mode, sizeof(mode));


  HAL_OTBN_DMEM_Write(RSA_OFFSET_D, (uint32_t *)key_d, num_bytes);
  // Set the base and the modulus n.
  HAL_OTBN_DMEM_Write(RSA_OFFSET_INOUT, (uint32_t *)in, num_bytes);
  HAL_OTBN_DMEM_Write(RSA_OFFSET_N, (uint32_t *)key_n, num_bytes);

  // Start OTBN.
  wc_ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);
  err = HAL_OTBN_Error_Bit_Get();
  if(err)
  {
      //printf("errors detected during an operation 0x%x",err);
      return WC_HW_E;
  }
    
  rsa_modexp_finalize(num_bytes/4, (uint32_t *)out);
  *outLen = num_bytes;

  return 0;
}


#endif //WOLFSSL_LINKEDSEMI_OTBN_DELEGATION_SERVER