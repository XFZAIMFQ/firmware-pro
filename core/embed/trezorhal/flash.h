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

#ifndef TREZORHAL_FLASH_H
#define TREZORHAL_FLASH_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "secbool.h"

#define USE_EXTERN_FLASH 1

#if USE_EXTERN_FLASH
    // 16 internal + 16 external code(2x64K)
  #define FLASH_SECTOR_COUNT           (32)
  #define FLASH_BOOTLOADER_SECTOR_SIZE (128 * 1024)
  #define FLASH_FIRMWARE_SECTOR_SIZE   (128 * 1024)
  #define FLASH_INNER_COUNT            16
#else
  #define FLASH_SECTOR_COUNT 16
#endif

#define FLASH_SECTOR_BOARDLOADER  0
#define FLASH_SECTOR_BOOTLOADER_1 1
#define FLASH_SECTOR_BOOTLOADER_2 2
#define FLASH_SECTOR_OTP_EMULATOR 15

#if USE_EXTERN_FLASH
  #define FLASH_SECTOR_FIRMWARE_START       3
  #define FLASH_SECTOR_FIRMWARE_END         14
  #define FLASH_SECTOR_FIRMWARE_EXTRA_START 16
  #define FLASH_SECTOR_FIRMWARE_EXTRA_END   31
#else
  #define FLASH_SECTOR_FIRMWARE_START 4
  #define FLASH_SECTOR_FIRMWARE_END   14
#endif

#define BOOTLOADER_SECTORS_COUNT     (2)
#define FIRMWARE_INNER_SECTORS_COUNT (12)
#define FIRMWARE_SECTORS_COUNT       (12 + 16)
// #define STORAGE_SECTORS_COUNT (2)

extern const uint8_t BOOTLOADER_SECTORS[BOOTLOADER_SECTORS_COUNT];
extern const uint8_t FIRMWARE_SECTORS[FIRMWARE_SECTORS_COUNT];

#define FLASH_STATUS_ALL_FLAGS \
  (FLASH_SR_PGSERR | FLASH_SR_PGPERR | FLASH_SR_PGAERR | FLASH_SR_WRPERR | FLASH_SR_SOP | FLASH_SR_EOP)

void flash_init(void);

secbool __wur flash_unlock_write(void);
secbool __wur flash_lock_write(void);

const void* flash_get_address(uint8_t sector, uint32_t offset, uint32_t size);
uint32_t flash_sector_size(uint8_t sector);
secbool __wur flash_erase_sectors(const uint8_t* sectors, int len, void (*progress)(int pos, int len));
static inline secbool flash_erase(uint8_t sector) {
    return flash_erase_sectors(&sector, 1, NULL);
}
secbool __wur flash_write_byte(uint8_t sector, uint32_t offset, uint8_t data);
secbool __wur flash_write_word(uint8_t sector, uint32_t offset, uint32_t data);
secbool __wur flash_write_words(uint8_t sector, uint32_t offset, uint32_t data[8]);

bool flash_check_ecc_fault();
bool flash_clear_ecc_fault(uint32_t address);
#if !PRODUCTION
bool flash_fix_ecc_fault_BOARDLOADER(uint32_t address);
#endif
bool flash_fix_ecc_fault_BOOTLOADER(uint32_t address);
bool flash_fix_ecc_fault_FIRMWARE(uint32_t address);
bool flash_fix_ecc_fault_FIRMWARE_v2(uint32_t address);

#define FLASH_OTP_NUM_BLOCKS 32
#define FLASH_OTP_BLOCK_SIZE 32

typedef struct __attribute__((packed))
{
    uint8_t flag[32];
    uint8_t flash_otp[FLASH_OTP_NUM_BLOCKS][FLASH_OTP_BLOCK_SIZE];
} FlashLockedData;

// OTP blocks allocation
#define FLASH_OTP_BLOCK_BATCH              0  // 批次号
#define FLASH_OTP_BLOCK_BOOTLOADER_VERSION 1  // 引导加载程序版本
#define FLASH_OTP_BLOCK_VENDOR_HEADER_LOCK 2  // 厂商头部锁定
#define FLASH_OTP_BLOCK_RANDOMNESS         3  // 随机数
#define FLASH_OTP_BLOCK_BURNIN_TEST        7  // 烧录测试
#define FLASH_OTP_BLOCK_THD89_SESSION_KEY  8  // THD89会话密钥
#define FLASH_OTP_DEVICE_SERIAL            12 // 设备序列号
#define FLASH_OTP_FACTORY_TEST             13 // 工厂测试
#define FLASH_OTP_RANDOM_KEY               14 // 随机密钥
#define FLASH_OTP_CPU_FIRMWARE_INFO        15 // CPU固件信息
#define FLASH_OTP_BLOCK_THD89_1_PUBKEY1    16 // THD89_1公钥1
#define FLASH_OTP_BLOCK_THD89_1_PUBKEY2    17 // THD89_1公钥2
#define FLASH_OTP_BLOCK_THD89_2_PUBKEY1    18 // THD89_2公钥1
#define FLASH_OTP_BLOCK_THD89_2_PUBKEY2    19 // THD89_2公钥2
#define FLASH_OTP_BLOCK_THD89_3_PUBKEY1    20 // THD89_3公钥1
#define FLASH_OTP_BLOCK_THD89_3_PUBKEY2    21 // THD89_3公钥2
#define FLASH_OTP_BLOCK_THD89_4_PUBKEY1    22 // THD89_4公钥1
#define FLASH_OTP_BLOCK_THD89_4_PUBKEY2    23 // THD89_4公钥2
#define FLASH_OTP_BLOCK_BLE_PUBKEY1        24 // BLE公钥1
#define FLASH_OTP_BLOCK_BLE_PUBKEY2        25 // BLE公钥2

extern FlashLockedData* flash_otp_data;

void flash_otp_init(void);
secbool __wur flash_otp_read(uint8_t block, uint8_t offset, uint8_t* data, uint8_t datalen);
secbool __wur flash_otp_write(uint8_t block, uint8_t offset, const uint8_t* data, uint8_t datalen);
secbool __wur flash_otp_lock(uint8_t block);
secbool __wur flash_otp_is_locked(uint8_t block);

void flash_test(void);

#endif // TREZORHAL_FLASH_H
