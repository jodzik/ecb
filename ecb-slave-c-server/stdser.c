#include "stdser.h"

void stdser_s16(uint16_t val, uint8_t* buf) {
	buf[0] = (uint8_t)((val >> 8) & 0xFF);
	buf[1] = (uint8_t)(val & 0xFF);
}

void stdser_s32(uint32_t val, uint8_t* buf) {
	buf[0] = (uint8_t)((val >> 24) & 0xFF);
	buf[1] = (uint8_t)((val >> 16) & 0xFF);
	buf[2] = (uint8_t)((val >> 8) & 0xFF);
	buf[3] = (uint8_t)(val & 0xFF);
}

uint16_t stdser_g16(const uint8_t* buf) {
	uint16_t t = 0;
	t |= buf[0] << 8;
	t |= buf[1];
	return t;
}

uint32_t stdser_g32(const uint8_t* buf) {
	uint32_t t = 0;
	t |= buf[0] << 24;
	t |= buf[1] << 16;
	t |= buf[2] << 8;
	t |= buf[3];
	return t;
}

size_t stdser_gstr(const uint8_t* buf, char* dst, size_t max_len) {
	size_t i;
	for (i = 0; i < max_len; i++) {
		dst[i] = buf[i];
		if (buf[i] == '\0') {
			return i + 1;
		}
	}
	dst[max_len - 1] = 0;
	return max_len;
}

size_t stdser_sstr(const char* val, uint8_t* buf, size_t max_len) {
	size_t i;
	for (i = 0; i < max_len; i++) {
		buf[i] = val[i];
		if (val[i] == '\0') {
			return i + 1;
		}
	}
	buf[max_len - 1] = 0;
	return max_len;
}
