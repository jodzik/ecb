#include "crc32.h"

#include <stdint.h>

uint32_t crc32(const uint8_t* data, size_t ndata) {
	uint32_t crc = 0;

	while(ndata--) {
		crc = crc ^ *data++;
		for(int bit = 0; bit < 8; bit++ ) {
			if(crc & 1) {
				crc = (crc >> 1) ^ CRC32_POLYNOME;
			} else {
				crc = (crc >> 1);
			}
		}
	}
    
	return crc;
}

uint32_t crc32_dync(uint32_t crc, uint8_t data) {
    crc = crc ^ data;
    for(int bit = 0; bit < 8; bit++ ) {
        if(crc & 1) {
            crc = (crc >> 1) ^ CRC32_POLYNOME;
        } else {
            crc = (crc >> 1);
        }
    }

	return crc;
}