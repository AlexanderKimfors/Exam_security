#ifndef WS2812B_H
#define WS2812B_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    bool ws2812b_init(void);

    void ws2812b_set_color(uint8_t _red, uint8_t _green, uint8_t _blue);

#ifdef __cplusplus
}
#endif

#endif
