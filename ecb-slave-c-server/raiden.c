#include "raiden.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void _raiden_encode_block(const uint32_t key[4], const uint32_t data[2], uint32_t result[2]) {
	uint32_t b0 = data[0];
	uint32_t b1 = data[1];
	uint32_t k[4] = { key[0], key[1], key[2], key[3] };
	uint32_t sk = 0;
	int i = 0;

	for (i = 0; i < RAIDEN__KEY_SIZE; i++)
	{
		sk = k[i % 4] = ((k[0] + k[1]) + ((k[2] + k[3]) ^ (k[0] << (k[2] & 0x1F))));
		b0 += ((sk + b1) << 9) ^ ((sk - b1) ^ ((sk + b1) >> 14));
		b1 += ((sk + b0) << 9) ^ ((sk - b0) ^ ((sk + b0) >> 14));
	}
	result[0] = b0;
	result[1] = b1;
}


static void _raiden_decode_block(const uint32_t key[4], const uint32_t data[2], uint32_t result[2]) {
	uint32_t b0 = data[0];
	uint32_t b1 = data[1];
	uint32_t k[4] = { key[0],key[1],key[2],key[3] };
	uint32_t subkeys[RAIDEN__KEY_SIZE] = {0};
	int i = 0;

	for (i = 0; i < RAIDEN__KEY_SIZE; i++) subkeys[i] = k[i % 4] = ((k[0] + k[1]) + ((k[2] + k[3]) ^ (k[0] << (k[2] & 0x1F))));

	for (i = RAIDEN__KEY_SIZE - 1; i >= 0; i--)
	{
		b1 -= ((subkeys[i] + b0) << 9) ^ ((subkeys[i] - b0) ^ ((subkeys[i] + b0) >> 14));
		b0 -= ((subkeys[i] + b1) << 9) ^ ((subkeys[i] - b1) ^ ((subkeys[i] + b1) >> 14));
	}
	result[0] = b0;
	result[1] = b1;
}

int raiden_encode(const uint8_t key[RAIDEN__KEY_SIZE], const uint8_t* data, uint8_t* buf, size_t ndata) {
	size_t i = 0;

	if (ndata % RAIDEN__BLOCK_SIZE != 0) {
		return -1;
	}

	for (i = 0; i < ndata; i += RAIDEN__BLOCK_SIZE) {
		_raiden_encode_block((uint32_t*)key, (uint32_t*)&data[i], (uint32_t*)&buf[i]);
	}

	return 0;
}

int raiden_decode(const uint8_t key[RAIDEN__KEY_SIZE], const uint8_t* data, uint8_t* buf, size_t ndata) {
	size_t i = 0;

	if (ndata % RAIDEN__BLOCK_SIZE != 0) {
		return -1;
	}

	for (i = 0; i < ndata; i += RAIDEN__BLOCK_SIZE) {
		_raiden_decode_block((uint32_t*)key, (uint32_t*)&data[i], (uint32_t*)&buf[i]);
	}

	return 0;
}

int raiden_encode_buf(const uint8_t key[RAIDEN__KEY_SIZE], uint8_t* data, size_t ndata) {
	size_t i = 0;
	uint8_t buf[RAIDEN__BLOCK_SIZE] = {0};

	if (ndata % RAIDEN__BLOCK_SIZE != 0) {
		return -1;
	}

	for (i = 0; i < ndata; i += RAIDEN__BLOCK_SIZE) {
		_raiden_encode_block((uint32_t*)key, (uint32_t*)&data[i], (uint32_t*)buf);
		memcpy(&data[i], buf, RAIDEN__BLOCK_SIZE);
	}

	return 0;
}

int raiden_decode_buf(const uint8_t key[RAIDEN__KEY_SIZE], uint8_t* data, size_t ndata) {
	size_t i = 0;
	uint8_t buf[RAIDEN__BLOCK_SIZE] = {0};

	if (ndata % RAIDEN__BLOCK_SIZE != 0) {
		return -1;
	}

	for (i = 0; i < ndata; i += RAIDEN__BLOCK_SIZE) {
		_raiden_decode_block((uint32_t*)key, (uint32_t*)&data[i], (uint32_t*)buf);
		memcpy(&data[i], buf, RAIDEN__BLOCK_SIZE);
	}

	return 0;
}
