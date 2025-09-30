/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include STM32_HAL_H

#include "lowlevel.h"
#include "common.h"
#include "flash.h"

#pragma GCC optimize( \
    "no-stack-protector")  // applies to all functions in this file

#if PRODUCTION
#define WANT_RDP_LEVEL (OB_RDP_LEVEL_2)     // PRODUCTION 期望的保护等级
#define WANT_WRP_SECTORS (OB_WRP_SECTOR_0)  // PRODUCTION 保护第0扇区 (boardloader)
#else
#define WANT_RDP_LEVEL (OB_RDP_LEVEL_0)     // DEVELOPMENT 期望的保护等级
#define WANT_WRP_SECTORS (0)               // DEVELOPMENT 不保护任何扇区
#endif

// BOR LEVEL 3: Reset level threshold is around 2.5 V
#define WANT_BOR_LEVEL (OB_BOR_LEVEL3) // BOR LEVEL 3: Reset level threshold is around 2.5 V

/**
 * @brief  CPU L1-Cache enable.
 * @param  None
 * @retval None
 */
void cpu_cache_enable(void) {
  /* Enable I-Cache */
  SCB_EnableICache();

  /* Enable D-Cache */
  SCB_EnableDCache();
}

void cpu_cache_disable(void) {
  /* Disable I-Cache */
  SCB_DisableICache();

  /* Disable D-Cache */
  SCB_DisableDCache();
}

/**
 * @brief  System Clock Configuration
 *         The system Clock is configured as follow :
 *            System Clock source            = PLL (HSE)
 *            SYSCLK(Hz)                     = 400000000 (CM7 CPU Clock)
 *            HCLK(Hz)                       = 200000000 (CM4 CPU, AXI and AHBs
 * Clock) AHB Prescaler                  = 2 D1 APB3 Prescaler              = 2
 * (APB3 Clock  100MHz) D2 APB1 Prescaler              = 2 (APB1 Clock  100MHz)
 *            D2 APB2 Prescaler              = 2 (APB2 Clock  100MHz)
 *            D3 APB4 Prescaler              = 2 (APB4 Clock  100MHz)
 *            HSE Frequency(Hz)              = 25000000
 *            PLL_M                          = 5
 *            PLL_N                          = 160
 *            PLL_P                          = 2
 *            PLL_Q                          = 4
 *            PLL_R                          = 2
 *            VDD(V)                         = 3.3
 *            Flash Latency(WS)              = 4
 * @param  None
 * @retval None
 */
void system_clock_config(void) {
  RCC_ClkInitTypeDef RCC_ClkInitStruct;
  RCC_OscInitTypeDef RCC_OscInitStruct;
  RCC_PeriphCLKInitTypeDef PeriphClkInitStruct;
  HAL_StatusTypeDef ret = HAL_OK;

  /*!< Supply configuration update enable */
  // HAL_PWREx_ConfigSupply(PWR_LDO_SUPPLY);
  HAL_PWREx_ConfigSupply(PWR_DIRECT_SMPS_SUPPLY);

  /* The voltage scaling allows optimizing the power consumption when the device
     is clocked below the maximum system frequency, to update the voltage
     scaling value regarding system frequency refer to product datasheet.  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  while (!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {
  }

  /* Enable HSE Oscillator and activate PLL with HSE as source */
  RCC_OscInitStruct.OscillatorType =
      RCC_OSCILLATORTYPE_HSI48 | RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
  RCC_OscInitStruct.HSIState = RCC_HSI_OFF;
  RCC_OscInitStruct.CSIState = RCC_CSI_OFF;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;

  RCC_OscInitStruct.PLL.PLLM = 5;
  RCC_OscInitStruct.PLL.PLLN = 160;
  RCC_OscInitStruct.PLL.PLLFRACN = 0;
  RCC_OscInitStruct.PLL.PLLP = 2;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  RCC_OscInitStruct.PLL.PLLR = 2;

  RCC_OscInitStruct.PLL.PLLVCOSEL = RCC_PLL1VCOWIDE;
  RCC_OscInitStruct.PLL.PLLRGE = RCC_PLL1VCIRANGE_2;
  ret = HAL_RCC_OscConfig(&RCC_OscInitStruct);
  if (ret != HAL_OK) {
    ensure(secfalse, "HAL_RCC_OscConfig failed");
  }

  /* Select PLL as system clock source and configure  bus clocks dividers */
  RCC_ClkInitStruct.ClockType =
      (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_D1PCLK1 |
       RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2 | RCC_CLOCKTYPE_D3PCLK1);

  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.SYSCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_APB3_DIV2;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_APB1_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_APB2_DIV2;
  RCC_ClkInitStruct.APB4CLKDivider = RCC_APB4_DIV2;
  ret = HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4);
  if (ret != HAL_OK) {
    ensure(secfalse, "HAL_RCC_ClockConfig failed");
  }

  PeriphClkInitStruct.PeriphClockSelection = RCC_PERIPHCLK_USB;
  PeriphClkInitStruct.UsbClockSelection = RCC_USBCLKSOURCE_HSI48;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct) != HAL_OK) {
    ensure(secfalse, "HAL_RCCEx_PeriphCLKConfig failed");
  }

  /*
   Note : The activation of the I/O Compensation Cell is recommended with
   communication  interfaces (GPIO, SPI, FMC, QSPI ...)  when  operating at high
   frequencies(please refer to product datasheet) The I/O Compensation Cell
   activation  procedure requires :
         - The activation of the CSI clock
         - The activation of the SYSCFG clock
         - Enabling the I/O Compensation Cell : setting bit[0] of register
   SYSCFG_CCCSR
  */

  /*activate CSI clock mondatory for I/O Compensation Cell*/
  __HAL_RCC_CSI_ENABLE();

  /* Enable SYSCFG clock mondatory for I/O Compensation Cell */
  __HAL_RCC_SYSCFG_CLK_ENABLE();

  /* Enables the I/O Compensation Cell */
  HAL_EnableCompensationCell();

  SCB->CPACR |=
      ((3UL << 10 * 2) | (3UL << 11 * 2)); /* set CP10 and CP11 Full Access */

  SystemCoreClockUpdate();
}

void periph_init(void) {
  // STM32F4xx HAL library initialization:
  //  - configure the Flash prefetch, instruction and data caches
  //  - configure the Systick to generate an interrupt each 1 msec
  //  - set NVIC Group Priority to 4
  //  - global MSP (MCU Support Package) initialization
  HAL_Init();

  // enable the PVD (programmable voltage detector).
  // select the "2.7V" threshold (level 5).
  // this detector will be active regardless of the
  // flash option byte BOR setting.

  PWR_PVDTypeDef pvd_config;
  pvd_config.PVDLevel = PWR_PVDLEVEL_5;
  pvd_config.Mode = PWR_PVD_MODE_IT_RISING_FALLING;
  HAL_PWR_ConfigPVD(&pvd_config);
  HAL_PWR_EnablePVD();
  NVIC_EnableIRQ(PVD_AVD_IRQn);
}

void reset_flags_reset(void) {
  RCC->RSR |= RCC_RSR_RMVF;  // clear the reset flags
}

void flash_option_bytes_init(void) {
  FLASH_OBProgramInitTypeDef ob_config;
  // 获取当前FLASHE配置
  HAL_FLASHEx_OBGetConfig(&ob_config);

  if (ob_config.RDPLevel != OB_RDP_LEVEL_2) {
    if ((ob_config.USERConfig & OB_BCM4_ENABLE) != OB_BCM4_DISABLE) {
      ob_config.OptionType |= OPTIONBYTE_USER;
      ob_config.USERType |= OB_USER_BCM4;
      ob_config.USERConfig &= ~OB_BCM4_ENABLE;

      HAL_FLASH_Unlock();
      HAL_FLASH_OB_Unlock();

      if (HAL_FLASHEx_OBProgram(&ob_config) != HAL_OK) {
        ensure(secfalse, "HAL_FLASHEx_OBProgram failed");
      }

      if (HAL_FLASH_OB_Launch() != HAL_OK) {
        ensure(secfalse, "HAL_FLASH_OB_Launch failed");
      }

      HAL_FLASH_OB_Lock();
      HAL_FLASH_Lock();
    }
  }

  // 设置期望的保护等级和保护扇区
  if (ob_config.RDPLevel != WANT_RDP_LEVEL) {
    ob_config.OptionType |=
        OPTIONBYTE_WRP | OPTIONBYTE_RDP | OPTIONBYTE_USER | OPTIONBYTE_BOR;
    ob_config.RDPLevel = WANT_RDP_LEVEL;  // 期望的保护等级
    ob_config.BORLevel = WANT_BOR_LEVEL;
    ob_config.WRPSector = WANT_WRP_SECTORS;// 期望保护的扇区
    ob_config.USERType =
        OB_USER_IWDG1_SW | OB_USER_IWDG2_SW | OB_USER_NRST_STOP_D1 |
        OB_USER_NRST_STOP_D2 | OB_USER_NRST_STDBY_D1 | OB_USER_NRST_STDBY_D2 |
        OB_USER_IWDG_STOP | OB_USER_IWDG_STDBY | OB_USER_IOHSLV |
        OB_USER_SWAP_BANK | OB_USER_SECURITY | OB_USER_BCM4;
    ob_config.USERConfig =
        OB_IWDG1_SW | OB_IWDG2_SW | OB_STOP_NO_RST_D1 | OB_STOP_NO_RST_D2 |
        OB_STDBY_NO_RST_D1 | OB_STDBY_NO_RST_D2 | OB_IWDG_STOP_FREEZE |
        OB_IWDG_STDBY_FREEZE | OB_IOHSLV_ENABLE | OB_SWAP_BANK_DISABLE |
        OB_SECURITY_DISABLE | OB_BCM4_DISABLE;

    HAL_FLASH_Unlock();
    HAL_FLASH_OB_Unlock();

    if (HAL_FLASHEx_OBProgram(&ob_config) != HAL_OK) {
      ensure(secfalse, "HAL_FLASHEx_OBProgram failed");
    }

    if (HAL_FLASH_OB_Launch() != HAL_OK) {
      ensure(secfalse, "HAL_FLASH_OB_Launch failed");
    }

    HAL_FLASH_OB_Lock();
    HAL_FLASH_Lock();

    HAL_FLASHEx_OBGetConfig(&ob_config);
  }
}

void bus_fault_enable(void) { SCB->SHCSR |= SCB_SHCSR_BUSFAULTENA_Msk; }
void bus_fault_disable(void) { SCB->SHCSR &= ~SCB_SHCSR_BUSFAULTENA_Msk; }
