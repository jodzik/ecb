#ifndef RAIDEN
#define RAIDEN

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

enum {
    RAIDEN__KEY_SIZE = 16,
};

void raiden_encode(const uint8_t key[16], const uint8_t* data, uint8_t* buf, size_t ndata);
void raiden_decode(const uint8_t key[16], const uint8_t* data, uint8_t* buf, size_t ndata);
void raiden_encode_buf(const uint8_t key[16], uint8_t* data, size_t ndata);
void raiden_decode_buf(const uint8_t key[16], uint8_t* data, size_t ndata);

#ifdef __cplusplus
}
#endif

#endif // !RAIDEN
