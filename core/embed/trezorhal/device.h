#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define PRODUCT_STRING "OneKey Pro"
#define SE_NAME        "THD89"

typedef struct __attribute__((packed))
{
    char product[2];
    char hardware[2];
    char color;
    char factory[2];
    char utc[10];
    char serial[7];
} DeviceSerialNo;

typedef struct __attribute__((packed))
{
    char serial[32];
    char cpu_info[16];
    char pre_firmware[16];
    uint32_t st_id[3];
    bool random_key_init;
    uint8_t random_key[32];
} DeviceInfomation;

typedef struct
{
    uint32_t flag;
    uint32_t time;
    uint32_t touch;
} test_result;

void device_set_factory_mode(bool mode);                            // 设置工厂模式
bool device_is_factory_mode(void);                                  // 是否工厂模式
void device_para_init(void);                                        // 设备参数初始化
bool device_serial_set(void);                                       // 设备序列号是否设置
bool device_set_serial(char* dev_serial);                           // 设置设备序列号
bool device_cpu_firmware_set(void);                                 // 设备CPU和固件信息是否设置
bool device_set_cpu_firmware(char* cpu_info, char* firmware_ver);   // 设置设备CPU和固件信息
bool device_get_cpu_firmware(char** cpu_info, char** firmware_ver); // 获取设备CPU和固件信息
bool device_get_serial(char** serial);                              // 获取设备序列号
char* device_get_se_config_version(void);                           // 获取安全芯片配置版本
void device_get_enc_key(uint8_t key[32]);                           // 获取加密密钥

void device_verify_ble(void); // 验证蓝牙

void device_test(bool force);             // 设备自检
void device_burnin_test(bool force);      // 设备烧录测试
void device_burnin_test_clear_flag(void); // 清除烧录测试标志
void device_generate_trng_data(void);     // 生成TRNG数据
;
#if !PRODUCTION
bool device_backup_otp(bool overwrite);         // 备份OTP
bool device_restore_otp();                      // 恢复OTP
bool device_overwrite_serial(char* dev_serial); // 覆盖设备序列号
#endif

#endif
