#ifndef RAIDEN
#define RAIDEN

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

enum {
    RAIDEN__KEY_SIZE = 16,
    RAIDEN__BLOCK_SIZE = 8,
};

int raiden_encode(const uint8_t key[RAIDEN__KEY_SIZE], const uint8_t* data, uint8_t* buf, size_t ndata);
int raiden_decode(const uint8_t key[RAIDEN__KEY_SIZE], const uint8_t* data, uint8_t* buf, size_t ndata);
int raiden_encode_buf(const uint8_t key[RAIDEN__KEY_SIZE], uint8_t* data, size_t ndata);
int raiden_decode_buf(const uint8_t key[RAIDEN__KEY_SIZE], uint8_t* data, size_t ndata);

#ifdef __cplusplus
}
#endif

#endif // !RAIDEN
