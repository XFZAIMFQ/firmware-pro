#ifndef _TXW700140K0_H_
#define _TXW700140K0_H_

#include <mipi_display.h>

// Lane Num=2 lane
// Frame rate：60Hz
// Pixel Clk：43.25MHz

#define TXW700140K0_LANE 2         // MIPI-DSI Lane count           // MIPI-DSI 通道数
#define TXW700140K0_PCLK 43250000  // Pixel Clk (Hz)                // 像素时钟频率(赫兹)
#define TXW700140K0_HRES 600       // Horizontal Resolution         // 水平分辨率
#define TXW700140K0_HSYNC 20       // Horizontal synchronization    // 水平同步
#define TXW700140K0_HBP 20         // Horizontal back porch         // 水平后廊
#define TXW700140K0_HFP 40         // Horizontal front porch        // 水平前廊
#define TXW700140K0_VRES 1024      // Vertical Resolution           // 垂直分辨率
#define TXW700140K0_VSYNC 5        // Vertical synchronization      // 垂直同步
#define TXW700140K0_VBP 8          // Vertical back porch           // 垂直后廊
#define TXW700140K0_VFP 24         // Vertical front porch          // 垂直前廊

int TXW700140K0_init_sequence(DSI_Writer_t dsi_writter, Delay_ms_uint32 delay_ms);

#endif
