#ifndef STDSER
#define STDSER

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

void stdser_s16(uint16_t val, uint8_t* buf);
void stdser_s32(uint32_t val, uint8_t* buf);

uint16_t stdser_g16(const uint8_t* buf);
uint32_t stdser_g32(const uint8_t* buf);

size_t stdser_gstr(const uint8_t* buf, char* dst, size_t max_len);
size_t stdser_sstr(const char* val, uint8_t* buf, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif // !STDSER
