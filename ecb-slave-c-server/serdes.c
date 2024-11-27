#include "serdes.h"

uint16_t u16_from_be(uint8_t const* const buf) {
    return (buf[0] << 8) | buf[1];
}

void u16_to_be(uint8_t* const buf, uint16_t const val) {
    buf[0] = (uint8_t)(val >> 8);
    buf[1] = (uint8_t)(val & 0xff);
}

uint32_t u32_from_be(uint8_t const* buf) {
    uint32_t val = 0;
    val |= (uint32_t)buf[0] << 24;
    val |= (uint32_t)buf[1] << 16;
    val |= (uint32_t)buf[2] << 8;
    val |= buf[3];

    return val;
}

void u32_to_be(uint8_t* buf, uint32_t val) {
    buf[0] = (uint8_t)(val >> 24);
    buf[1] = (uint8_t)(val >> 16);
    buf[2] = (uint8_t)(val >> 8);
    buf[3] = (uint8_t)(val & 0xff);
}
