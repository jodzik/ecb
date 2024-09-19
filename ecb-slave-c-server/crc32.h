#ifndef CRC32
#define CRC32

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

#define CRC32_POLYNOME      0x04C11DB7

uint32_t crc32(const uint8_t* data, size_t ndata);
uint32_t crc32_dync(uint32_t crc, uint8_t data);

#ifdef __cplusplus
}
#endif

#endif // !CRC32