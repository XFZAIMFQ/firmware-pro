#ifndef __CAMERA_QRCODE_H__
#define __CAMERA_QRCODE_H__

#include <stdint.h>

int camera_qr_decode(uint32_t x, uint32_t y, uint8_t* data, uint32_t data_len); // 二维码解码
void camera_qr_test(void);                                                      // 二维码测试

#endif // __CAMERA_QRCODE_H__
