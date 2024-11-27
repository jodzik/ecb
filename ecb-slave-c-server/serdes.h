#ifndef SERDES_H_
#define SERDES_H_

#include <stdint.h>

uint16_t u16_from_be(uint8_t const* buf);
void u16_to_be(uint8_t* buf, uint16_t val);

uint32_t u32_from_be(uint8_t const* buf);
void u32_to_be(uint8_t* buf, uint32_t val);

#endif