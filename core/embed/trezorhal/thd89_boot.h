#ifndef _THD89_BOOT_H_
#define _THD89_BOOT_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define THD89_STATE_BOOT          0x00
#define THD89_STATE_NOT_ACTIVATED 0x33
#define THD89_STATE_APP           0x55

enum
{
    THD89_1ST_IN_BOOT = 0x01,
    THD89_2ND_IN_BOOT = 0x02,
    THD89_3RD_IN_BOOT = 0x04,
    THD89_4TH_IN_BOOT = 0x08
};

void thd89_boot_set_address(uint8_t addr);                      // 设置当前操作的地址
uint8_t se_get_state(void);                                     // 获取状态
bool se_get_state_ex(uint8_t* state);                           // 获取当前操作的状态
char* se_get_version_ex(void);                                  // 获取当前操作的版本
bool se_back_to_boot(void);                                     // 回到boot
bool se_active_app(void);                                       // 激活app
bool se_update(uint8_t step, uint8_t* data, uint16_t data_len); // 更新
bool se_back_to_boot_progress(void);                            // 回到boot进度
bool se_update_firmware(
    uint8_t* data,
    uint32_t data_len,
    uint8_t percent_start,
    uint8_t weights,
    void (*ui_callback)(int progress)
);                                                             // 更新固件
bool se_active_app_progress(void);                             // 激活app进度
bool se_verify_firmware(uint8_t* header, uint32_t header_len); // 验证固件
bool se_check_firmware(void);                                  // 检查固件

bool se01_get_state(uint8_t* state);
bool se02_get_state(uint8_t* state);
bool se03_get_state(uint8_t* state);
bool se04_get_state(uint8_t* state);
#endif
