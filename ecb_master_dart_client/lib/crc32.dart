import 'dart:typed_data';

int crc32(ByteData data, int realLen) {
  const polymone = 0x04C11DB7;
  int crc = 0;

  for (var i = 0; i < realLen; i++) {
    crc = crc ^ data.getUint8(i);
    crc = crc.toUnsigned(32);
    for (int bit = 0; bit < 8; bit++) {
      if (crc & 1 > 0) {
        crc = (crc >> 1) ^ polymone;
        crc = crc.toUnsigned(32);
      } else {
        crc = (crc >> 1);
        crc = crc.toUnsigned(32);
      }
    }
  }

  return crc;
}

int crc32_dync(int crc, int data) {
  const polymone = 0x04C11DB7;
  crc = crc ^ data;
  crc = crc.toUnsigned(32);
  for (int bit = 0; bit < 8; bit++) {
    if (crc & 1 > 0) {
      crc = (crc >> 1) ^ polymone;
      crc = crc.toUnsigned(32);
    } else {
      crc = (crc >> 1);
      crc = crc.toUnsigned(32);
    }
  }

  return crc;
}
