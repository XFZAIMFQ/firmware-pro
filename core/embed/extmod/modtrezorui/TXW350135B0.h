#ifndef _TXW350135B0_H_
#define _TXW350135B0_H_

#include <mipi_display.h>

#define TXW350135B0_TWO_LANE

#if defined(TXW350135B0_ONE_LANE)

// Lane Num=1 lane
// Frame rate：60.05Hz
// Pixel Clk：33.00Mhz

#define TXW350135B0_LANE 1         // MIPI-DSI Lane count
#define TXW350135B0_PCLK 33000000  // Pixel Clk (Hz)
#define TXW350135B0_HRES 480       // Horizontal Resolution
#define TXW350135B0_HSYNC 8        // Horizontal synchronization
#define TXW350135B0_HBP 80         // Horizontal back porch
#define TXW350135B0_HFP 80         // Horizontal front porch
#define TXW350135B0_VRES 800       // Vertical Resolution
#define TXW350135B0_VSYNC 8        // Vertical synchronization
#define TXW350135B0_VBP 20         // Vertical back porch
#define TXW350135B0_VFP 20         // Vertical front porch

#elif defined(TXW350135B0_TWO_LANE)

// Lane Num=2 lane
// Frame rate：60.00Hz
// Pixel Clk：32.97Mhz

#define TXW350135B0_LANE 2         // MIPI-DSI Lane count           // MIPI-DSI 通道数
#define TXW350135B0_PCLK 32970000  // Pixel Clk (Hz)                // 像素时钟频率(赫兹)
#define TXW350135B0_HRES 480       // Horizontal Resolution         // 水平分辨率
#define TXW350135B0_HSYNC 8        // Horizontal synchronization    // 水平同步
#define TXW350135B0_HBP 80         // Horizontal back porch         // 水平后廊
#define TXW350135B0_HFP 80         // Horizontal front porch        // 水平前廊
#define TXW350135B0_VRES 800       // Vertical Resolution           // 垂直分辨率
#define TXW350135B0_VSYNC 8        // Vertical synchronization      // 垂直同步
#define TXW350135B0_VBP 20         // Vertical back porch           // 垂直后廊
#define TXW350135B0_VFP 20         // Vertical front porch          // 垂直前廊

#else
#error "TXW350135B0 lane selection not defined!"
#endif

int TXW350135B0_init_sequence(DSI_Writer_t dsi_writter,Delay_ms_uint32 delay_ms);

#endif
