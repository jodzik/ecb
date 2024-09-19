import 'dart:typed_data';

const u32Max = 4294967295;

int toU32(int val) {
  if (val > u32Max) {
    return val - u32Max - 1;
  } else if (val < 0) {
    return u32Max + val + 1;
  } else {
    return val;
  }
}

class Raiden {
  ByteData _key;

  Raiden(this._key);

  ByteData encrypt(ByteData data) {
    if (data.lengthInBytes % 8 != 0) {
      throw const FormatException("data must be multiple at 8 byte block");
    }
    var result = <int>[];
    for (var i = 0; i < data.lengthInBytes; i += 8) {
      var block = ByteData.sublistView(data, i, i + 8);
      var encBlock = _encryptBlock(block);
      for (var j = 0; j < 8; j++) {
        result.add(encBlock.getUint8(j));
      }
    }
    return ByteData.view(Uint8List.fromList(result).buffer);
  }

  ByteData decrypt(ByteData data) {
    if (data.lengthInBytes % 8 != 0) {
      throw const FormatException("data must be multiple at 8 byte block");
    }
    var result = <int>[];
    for (var i = 0; i < data.lengthInBytes; i += 8) {
      var block = ByteData.sublistView(data, i, i + 8);
      var encBlock = _decryptBlock(block);
      for (var j = 0; j < 8; j++) {
        result.add(encBlock.getUint8(j));
      }
    }
    return ByteData.view(Uint8List.fromList(result).buffer);
  }

  void setKey(ByteData key) {
    _key = key;
  }

  // default C representation use little endian

  ByteData _encryptBlock(ByteData data) {
    var b0 = data.getUint32(0, Endian.little);
    var b1 = data.getUint32(4, Endian.little);
    var k = [
      _key.getUint32(0, Endian.little),
      _key.getUint32(4, Endian.little),
      _key.getUint32(8, Endian.little),
      _key.getUint32(12, Endian.little)
    ];
    var sk = 0;
    var tmp = 0;
    for (var i = 0; i < 16; i++) {
      var k01 = k[0] + k[1];
      k01 = toU32(k01);
      var k23 = k[2] + k[3];
      k23 = toU32(k23);
      var kbwo = k23 ^ (k[0] << (k[2] & 0x1F));
      kbwo = kbwo.toUnsigned(32);
      tmp = k01 + kbwo;
      tmp = toU32(tmp);
      sk = k[i % 4] = tmp;
      var skpb1 = sk + b1;
      skpb1 = toU32(skpb1);
      var skmb1 = sk - b1;
      skmb1 = toU32(skmb1);
      var skb1bwo = ((skpb1) << 9) ^ ((skmb1) ^ ((skpb1) >> 14));
      skb1bwo = skb1bwo.toUnsigned(32);
      b0 += skb1bwo;
      b0 = toU32(b0);
      var skpb0 = sk + b0;
      skpb0 = toU32(skpb0);
      var skmb0 = sk - b0;
      skmb0 = toU32(skmb0);
      var skb0bwo = ((skpb0) << 9) ^ ((skmb0) ^ ((skpb0) >> 14));
      skb0bwo = skb0bwo.toUnsigned(32);
      b1 += skb0bwo;
      b1 = toU32(b1);
    }
    var result = ByteData(8);
    result.setUint32(0, b0, Endian.little);
    result.setUint32(4, b1, Endian.little);
    return result;
  }

  ByteData _decryptBlock(ByteData data) {
    var b0 = data.getUint32(0, Endian.little);
    var b1 = data.getUint32(4, Endian.little);
    var k = [
      _key.getUint32(0, Endian.little),
      _key.getUint32(4, Endian.little),
      _key.getUint32(8, Endian.little),
      _key.getUint32(12, Endian.little)
    ];
    var subkeys = Uint32List(16);
    for (var i = 0; i < 16; i++) {
      var k01 = k[0] + k[1];
      k01 = toU32(k01);
      var k23 = k[2] + k[3];
      k23 = toU32(k23);
      var kbwo = k23 ^ (k[0] << (k[2] & 0x1F));
      kbwo = kbwo.toUnsigned(32);
      var tmp = k01 + kbwo;
      tmp = toU32(tmp);
      tmp.toUnsigned(32);
      subkeys[i] = k[i % 4] = tmp;
    }

    for (var i = 15; i >= 0; i--) {
      var skpb0 = subkeys[i] + b0;
      skpb0 = toU32(skpb0);
      var skmb0 = subkeys[i] - b0;
      skmb0 = toU32(skmb0);
      var skb0bwo = ((skpb0) << 9) ^ ((skmb0) ^ ((skpb0) >> 14));
      skb0bwo = skb0bwo.toUnsigned(32);
      b1 -= skb0bwo;
      b1 = toU32(b1);
      var skpb1 = subkeys[i] + b1;
      skpb1 = toU32(skpb1);
      var skmb1 = subkeys[i] - b1;
      skmb1 = toU32(skmb1);
      var skb1bwo = ((skpb1) << 9) ^ ((skmb1) ^ ((skpb1) >> 14));
      skb1bwo = skb1bwo.toUnsigned(32);
      b0 -= skb1bwo;
      b0 = toU32(b0);
    }
    var result = ByteData(8);
    result.setUint32(0, b0, Endian.little);
    result.setUint32(4, b1, Endian.little);
    return result;
  }
}
