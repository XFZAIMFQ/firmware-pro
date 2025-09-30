#ifndef _TREZORHAL_THD89_H_
#define _TREZORHAL_THD89_H_

#include "secbool.h"

#define THD89_1ST_ADDRESS    (0x10 << 1)
#define THD89_2ND_ADDRESS    (0x11 << 1)
#define THD89_3RD_ADDRESS    (0x12 << 1)
#define THD89_4TH_ADDRESS    (0x13 << 1)

#define THD89_MASTER_ADDRESS THD89_1ST_ADDRESS
#define THD89_FINGER_ADDRESS THD89_4TH_ADDRESS

extern int thd89_irq_nest;

void thd89_io_init(void);                                                              // thd89-io 初始化
void thd89_init(void);                                                                 // thd89    初始化
void thd89_power_up(bool up);                                                          // 电源thd89
void thd89_reset(void);                                                                // 重置thd89
secbool thd89_transmit(uint8_t* cmd, uint16_t len, uint8_t* resp, uint16_t* resp_len); // 通信thd89
secbool thd89_fp_transmit(uint8_t* cmd, uint16_t len, uint8_t* resp, uint16_t* resp_len);               //
secbool thd89_transmit_ex(uint8_t addr, uint8_t* cmd, uint16_t len, uint8_t* resp, uint16_t* resp_len); //
uint16_t thd89_last_error();                                                                            //

#endif
