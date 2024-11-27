#ifndef CRC32
#define CRC32

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

// Reflected input: false
// Reflected result: false

enum {
    CRC32_POLYNOMIAL = 0x04C11DB7,
};

uint32_t crc32(const uint8_t* data, size_t ndata);
uint32_t crc32_cont_start(void);
uint32_t crc32_cont(uint32_t crc, uint8_t data);
uint32_t crc32_cont_finish(uint32_t crc);

#ifdef __cplusplus
}
#endif

#endif // !CRC32