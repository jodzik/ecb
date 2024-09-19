import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mutex/mutex.dart';
import 'package:tlv_decoder/tlv_decoder.dart';

import 'crc32.dart';
import 'raiden.dart';

abstract class EcbmIoInterface {
  Future<void> write(ByteData data);
  Future<ByteData> read();
  Future<void> dispose();
}

class EcbmEncSession {
  int addr;
  ByteData key;

  EcbmEncSession(this.addr, this.key);
}

class EcbmSig {
  static const reset = 0;
  static const info = 1;
  static const boardName = 2;
  static const save = 3;
  static const pick = 15;
  static const bootBegin = 16;
  static const bootEnd = 17;
  static const bootChecksum = 18;
  static const bootWrite = 20;
  static const bootFwInfo = 22;
  static const authKey = 24;
}

class EcbmResetParam {
  static const none = 0;
  static const longBoot = 1;
}

class EcbmDevInfo {
  static const int tlvCodeName = 1;
  static const int tlvCodeVersion = 2;
  static const int tlvCodeSerial = 3;
  String? name;
  List<int>? version;
  String? serial;

  EcbmDevInfo({this.name, this.version, this.serial});

  EcbmDevInfo.fromAnswer(ByteData infoAnswer) {
    List<TLV> tlvs = TlvUtils.decode(Uint8List.view(infoAnswer.buffer));
    for (final tlv in tlvs) {
      if (tlvCodeName == tlv.type) {
        name = utf8.decode(tlv.value, allowMalformed: true);
      } else if (tlvCodeVersion == tlv.type) {
        version = List.filled(3, 0);
        version![0] = tlv.value[0];
        version![1] = tlv.value[1];
        version![2] = tlv.value[2];
      } else if (tlvCodeSerial == tlv.type) {
        serial = utf8.decode(tlv.value, allowMalformed: true);
      }
    }
  }

  List<TLV> toTlv() {
    List<TLV> tlvs = List.empty(growable: true);
    if (name != null) {
      var nameRaw = utf8.encode(name!);
      tlvs.add(TLV(type: tlvCodeName, length: nameRaw.length, value: nameRaw));
    }
    if (version != null) {
      tlvs.add(TLV(
          type: tlvCodeVersion,
          length: 3,
          value: Uint8List.fromList(version!)));
    }
    if (serial != null) {
      var serialRaw = utf8.encode(serial!);
      tlvs.add(
          TLV(type: tlvCodeSerial, length: serialRaw.length, value: serialRaw));
    }
    return tlvs;
  }

  @override
  String toString() {
    String info = "EcbmDevInfo(";
    info += name == null ? "" : "name=${name!}";
    info += version == null ? "" : " version=${version!.toString()}";
    info += serial == null ? "" : " serial=${serial!}";
    info += ")";
    return info;
  }
}

class Ecbm {
  static final int _mark = int.parse("10000000", radix: 2);
  static final int _beginMark = int.parse("11010100", radix: 2);
  static final int _endMark = int.parse("10000001", radix: 2);
  static const _encFiller = 0x5A;
  static final int _pdDirMask = int.parse("00010000", radix: 2);
  static final int _pdIsEncMask = int.parse("00100000", radix: 2);
  static final int _pdTypeMask = int.parse("00001111", radix: 2);
  static final int _pdDirReq = int.parse("00010000", radix: 2);
  static final int _pdDirAnsw = int.parse("00000000", radix: 2);
  static final int _pdTypeWrite = int.parse("00000000", radix: 2);
  static final int _pdTypeWriteNoAnsw = int.parse("00000010", radix: 2);
  static final int _pdTypeWriteAuthReq = int.parse("00000111", radix: 2);
  static final int _pdTypeWriteAuth = int.parse("00001000", radix: 2);
  static final int _pdTypeRead = int.parse("00000001", radix: 2);
  static final int _pdTypeStreamOpen = int.parse("00000011", radix: 2);
  static final int _pdTypeStreamClose = int.parse("00000100", radix: 2);
  static final int _pdTypeStreamData = int.parse("00000101", radix: 2);
  static final int _pdTypeEncs = int.parse("00000110", radix: 2);
  static final int _pdTypeErr = int.parse("00001111", radix: 2);
  static const broadcastAddress = 0;
  static const int tlvCodeTestPhrase = 4;
  static const int tlvCodeFwSize = 5;

  final EcbmIoInterface io;
  final List<EcbmEncSession> _encSessions = <EcbmEncSession>[];
  Duration waitBeginMarkTimeout = const Duration(milliseconds: 500);
  Duration receiveFrameBytesTimeout = const Duration(milliseconds: 250);
  Duration transferSendReceiveDelay = const Duration(milliseconds: 10);
  final int _minTries = 3;
  final m = Mutex();
  Function(ByteData)? _onStreamData;
  int _streamSig = -1;
  int _streamAddr = -1;

  Ecbm(this.io) {
    _streamDataThread();
  }

  void setReceiveFrameBeginMarkTimeout(Duration timeout) {
    waitBeginMarkTimeout = timeout;
  }

  void setReceiveFrameBytesTimeout(Duration timeout) {
    receiveFrameBytesTimeout = timeout;
  }

  Future<void> beginEncSession(int addr, ByteData key) async {
    dropEncSession(addr);
    var rawAnsw = await _read(addr, 0, _pdTypeEncs, null);
    if (rawAnsw.lengthInBytes != 16) {
      throw const FormatException("incorrect key length in answer");
    }
    var raiden = Raiden(key);
    var sessionKey = raiden.decrypt(rawAnsw);
    _encSessions.add(EcbmEncSession(addr, sessionKey));
  }

  void dropEncSession(int addr) {
    var index = -1;
    for (var i = 0; i < _encSessions.length; i++) {
      if (_encSessions[i].addr == addr) {
        index = i;
        break;
      }
    }
    if (index >= 0) {
      _encSessions.removeAt(index);
    }
  }

  void dropAllEncSessions() {
    _encSessions.clear();
  }

  Future<void> setNewAuthKey(int addr, ByteData newKey) async {
    await write(addr, EcbmSig.authKey, newKey);
  }

  Future<EcbmDevInfo> readInfo(int addr) async {
    var rawAnsw = await read(addr, EcbmSig.info);
    return EcbmDevInfo.fromAnswer(rawAnsw);
  }

  Future<void> save(int addr) async {
    await write(addr, EcbmSig.save, ByteData(0));
  }

  Future<void> pick(int addr) async {
    await write(addr, EcbmSig.pick, ByteData(0));
  }

  Future<void> beginUploadFirmware(int addr, EcbmDevInfo newInfo,
      Uint8List testPhrase, int fwSize, Duration timeout) async {
    List<TLV> tlv = newInfo.toTlv();
    tlv.add(TLV(
        type: tlvCodeTestPhrase, length: testPhrase.length, value: testPhrase));
    ByteData fwSizeByteData = ByteData(4);
    fwSizeByteData.setUint32(0, fwSize);
    Uint8List fwSizeRaw = Uint8List.view(fwSizeByteData.buffer);
    tlv.add(TLV(type: tlvCodeFwSize, length: 4, value: fwSizeRaw));
    await write(
        addr, EcbmSig.bootBegin, ByteData.view(TlvUtils.encode(tlv).buffer),
        waitTimeout: timeout);
  }

  Future<void> writeFirmwareBlock(
      int addr, ByteData data, int address, Duration timeout) async {
    var fullData = ByteData(data.lengthInBytes + 4);
    fullData.setUint32(0, address);
    for (var i = 0; i < data.lengthInBytes; i++) {
      fullData.setUint8(4 + i, data.getUint8(i));
    }
    await write(addr, EcbmSig.bootWrite, fullData, waitTimeout: timeout);
  }

  Future<void> endUploadFirmware(
      int addr, int checksum, int length, Duration timeout) async {
    var data = ByteData(8);
    data.setUint32(0, checksum);
    data.setUint32(4, length);
    await write(addr, EcbmSig.bootEnd, data, waitTimeout: timeout);
  }

  Future<int> firmwareChecksum(int addr) async {
    var rawAnsw = await read(addr, EcbmSig.bootChecksum);
    return rawAnsw.getUint32(0);
  }

  Future<EcbmDevInfo> firmwareInfo(int addr) async {
    var rawAnsw = await read(addr, EcbmSig.bootFwInfo);
    return EcbmDevInfo.fromAnswer(rawAnsw);
  }

  Future<void> reset(int addr, [int resetParam = EcbmResetParam.none]) async {
    var req = ByteData(1);
    req.setUint8(0, resetParam);
    await writeNoAnswer(addr, EcbmSig.reset, req);
  }

  Future<void> write(int addr, int sig, ByteData data,
      {bool isEnc = false,
      Duration? waitTimeout,
      Duration? receiveTimeout}) async {
    await m.acquire();
    try {
      ByteData? encKey;
      if (isEnc) {
        encKey = getSessionKey(addr, true)!;
      }
      await _write(addr, _pdTypeWrite, sig, data, encKey,
          waitTimeout: waitTimeout, receiveTimeout: receiveTimeout);
    } catch (e) {
      rethrow;
    } finally {
      m.release();
    }
  }

  Future<void> writeNoAnswer(int addr, int sig, ByteData data,
      {bool isEnc = false}) async {
    await m.acquire();
    try {
      ByteData? encKey;
      if (isEnc) {
        encKey = getSessionKey(addr, true)!;
      }
      var packet = _makePacket(addr, _pdTypeWriteNoAnsw, sig, data, encKey);
      await _sendPacket(packet);
    } catch (e) {
      rethrow;
    } finally {
      m.release();
    }
  }

  Future<void> writeAuth(int addr, int sig, ByteData data,
      {Duration? waitTimeout, Duration? receiveTimeout}) async {
    await m.acquire();
    try {
      ByteData encKey = getSessionKey(addr, true)!;
      ByteData sign = await _read(addr, sig, _pdTypeWriteAuthReq, null);
      if (sign.lengthInBytes != 8) {
        throw FormatException(
            "sign size must be 8, but ${sign.lengthInBytes} given");
      }
      ByteData dataWithSign = ByteData(data.lengthInBytes + 8);
      for (int i = 0; i < 8; i++) {
        dataWithSign.setUint8(i, sign.getUint8(i));
      }
      for (int i = 0; i < data.lengthInBytes; i++) {
        dataWithSign.setUint8(i + 8, data.getUint8(i));
      }
      await _write(addr, _pdTypeWriteAuth, sig, dataWithSign, encKey,
          waitTimeout: waitTimeout, receiveTimeout: receiveTimeout);
    } catch (e) {
      rethrow;
    } finally {
      m.release();
    }
  }

  Future<ByteData> read(int addr, int sig,
      {bool isEnc = false,
      Duration? waitTimeout,
      Duration? receiveTimeout}) async {
    await m.acquire();
    try {
      ByteData? encKey;
      if (isEnc) {
        encKey = getSessionKey(addr, true)!;
      }
      return await _read(addr, sig, _pdTypeRead, encKey,
          waitTimeout: waitTimeout, receiveTimeout: receiveTimeout);
    } catch (e) {
      rethrow;
    } finally {
      m.release();
    }
  }

  Future<void> streamOpen(int addr, int sig, Function(ByteData) onData,
      {bool isEnc = false}) async {
    await m.acquire();
    try {
      ByteData? encKey;
      if (isEnc) {
        encKey = getSessionKey(addr, true)!;
      }
      await _write(addr, _pdTypeStreamOpen, sig, ByteData(0), encKey);
      _streamSig = sig;
      _onStreamData = onData;
      _streamAddr = addr;
    } catch (e) {
      rethrow;
    } finally {
      m.release();
    }
  }

  Future<void> streamClose(int addr) async {
    if (addr == broadcastAddress) {
      throw Exception(
          "Close stream by broadcast address provided by streamCloseAll");
    }
    _stopStreamReceive();
    await m.acquire();
    await Future.delayed(const Duration(milliseconds: 10));
    try {
      int tries = 0;
      while (true) {
        try {
          await _write(addr, _pdTypeStreamClose, 0, ByteData(0), null);
          break;
        } catch (e) {
          tries++;
          if (tries >= 3) {
            rethrow;
          }
          print("Fail to $tries try close stream: $e");
        }
      }
    } catch (e) {
      rethrow;
    } finally {
      m.release();
    }
  }

  Future<void> streamCloseAll() async {
    _stopStreamReceive();
    await m.acquire();
    try {
      var packet = _makePacket(
          broadcastAddress, _pdTypeStreamClose, 0, ByteData(0), null);
      await _sendPacket(packet);
    } catch (e) {
      rethrow;
    } finally {
      m.release();
    }
  }

  void _stopStreamReceive() {
    _onStreamData = null;
    _streamSig = -1;
    _streamAddr = -1;
  }

  Future<void> _streamDataThread() async {
    while (true) {
      if (_onStreamData != null) {
        await m.acquire();
        try {
          ByteData frame = await _receiveFrame();
          ByteData packet = _decodeFrame(frame);
          ByteData data = _assertAnswerAndDecrypt(
              _streamAddr,
              _pdTypeStreamData,
              _streamSig,
              getSessionKey(_streamAddr),
              packet);
          _onStreamData!(data);
        } catch (e) {
          print("Fail to receive stream data: $e");
        }
        m.release();
      } else {
        await Future.delayed(const Duration(milliseconds: 10));
      }
    }
  }

  Future<void> _write(
      int addr, int pdType, int sig, ByteData data, ByteData? encKey,
      {Duration? waitTimeout, Duration? receiveTimeout}) async {
    if (_onStreamData != null) {
      throw Exception(
          "Write operation not permitted until exists active stream");
    }
    if (addr == broadcastAddress) {
      throw Exception("Write by broadcast address not allowed, "
          "use writeWithoutAnswer for write by broadcast");
    }
    var packet = _makePacket(addr, pdType, sig, data, encKey);
    var answerPacket = await _transferPacket(packet,
        waitTimeout: waitTimeout, receiveTimeout: receiveTimeout);
    _assertAnswerAndDecrypt(addr, pdType, sig, encKey, answerPacket);
  }

  Future<ByteData> _read(int addr, int sig, int pdType, ByteData? encKey,
      {Duration? waitTimeout, Duration? receiveTimeout}) async {
    if (_onStreamData != null) {
      throw Exception(
          "Read operation not permitted until exists active stream");
    }
    if (addr == broadcastAddress) {
      throw const FormatException("addr for read must be non broadcast");
    }
    var packet = _makePacket(addr, pdType, sig, ByteData(0), encKey);
    var answerPacket = await _transferPacket(packet,
        waitTimeout: waitTimeout, receiveTimeout: receiveTimeout);
    return _assertAnswerAndDecrypt(addr, pdType, sig, encKey, answerPacket);
  }

  // Return Data
  ByteData _assertAnswerAndDecrypt(
      int addr, int pdType, int sig, ByteData? encKey, ByteData packet) {
    if (packet.lengthInBytes < 9) {
      throw const FormatException("packet len too small");
    }
    var crcReceived = packet.getUint32(packet.lengthInBytes - 4);
    var crcCalc = crc32(packet, packet.lengthInBytes - 4);
    if (crcReceived != crcCalc) {
      throw const FormatException("crc mismatch");
    }
    ByteData data = ByteData(packet.lengthInBytes - 9);
    for (int i = 0; i < packet.lengthInBytes - 9; i++) {
      data.setUint8(i, packet.getUint8(i + 5));
    }
    if (addr != packet.getUint8(0)) {
      throw const FormatException("addr mismatch");
    }

    var pd = packet.getUint8(1);
    bool isEnc = pd & _pdIsEncMask == _pdIsEncMask;
    if (isEnc && encKey == null) {
      throw const FormatException(
          "data in answer was encrypted, but enc key not provided");
    }
    if (isEnc) {
      var nfill = packet.getUint8(4);
      if (nfill > 7) {
        throw const FormatException("nfill field in packet more then 7");
      }
      int dataSize = packet.lengthInBytes - (9 + nfill);
      if (dataSize < 0) {
        throw FormatException(
            "data size < 0: total=${packet.lengthInBytes} nfill=$nfill");
      }
      var raiden = Raiden(encKey!);
      ByteData decryptedPart = raiden.decrypt(data);
      data = ByteData(dataSize);
      for (int i = 0; i < dataSize; i++) {
        data.setUint8(i, decryptedPart.getUint8(i));
      }
    }

    if (pd & _pdDirMask != _pdDirAnsw) {
      throw const FormatException("PD is't have answer direction");
    }
    if (pd & _pdTypeMask == _pdTypeErr) {
      int err = data.getUint8(0);
      var description = String.fromCharCodes(Uint8List.sublistView(data, 1));
      throw FormatException("Error response($err): $description");
    }
    if (pd & _pdTypeMask != pdType) {
      int actual = pd & _pdTypeMask;
      throw FormatException("PD type mismatch actual=$actual desired=$pdType");
    }

    int sigRecv = packet.getUint16(2);
    if (sigRecv != sig) {
      throw FormatException(
          "Response signal mismatch: received=$sigRecv desired=$sig");
    }

    return data;
  }

  // Put RawData
  // Return Packet
  ByteData _makePacket(
      int addr, int pdType, int sig, ByteData data, ByteData? encKey) {
    var nfill = encKey == null ? 0 : 8 - ((data.lengthInBytes) % 8);
    if (nfill == 8) {
      nfill = 0;
    }
    var buf = ByteData(data.lengthInBytes + 9 + nfill);
    buf.setUint8(0, addr);
    int isEnc = encKey == null ? 0 : _pdIsEncMask;
    buf.setUint8(1, _pdDirReq | pdType | isEnc);
    buf.setUint16(2, sig);
    buf.setUint8(4, nfill);
    var encryptedPart = ByteData(data.lengthInBytes + nfill);
    for (int i = 0; i < data.lengthInBytes; i++) {
      encryptedPart.setUint8(i, data.getUint8(i));
    }
    for (int i = 0; i < nfill; i++) {
      encryptedPart.setUint8(data.lengthInBytes + i, _encFiller);
    }
    if (encKey != null) {
      var raiden = Raiden(encKey);
      encryptedPart = raiden.encrypt(encryptedPart);
    }

    for (int i = 0; i < encryptedPart.lengthInBytes; i++) {
      buf.setUint8(i + 5, encryptedPart.getUint8(i));
    }
    buf.setUint32(encryptedPart.lengthInBytes + 5,
        crc32(buf, encryptedPart.lengthInBytes + 5));

    return buf;
  }

  // Framing == 7b encoding and mark bytes

  // Encode packet to frame and send, receive answer frame, decode to packet.
  // Put Packet
  // Return Packet
  Future<ByteData> _transferPacket(ByteData packet,
      {Duration? waitTimeout, Duration? receiveTimeout}) async {
    var swatch = Stopwatch();
    swatch.start();
    await _flushRead();
    await _sendFrame(_encodeFrame(packet));
    print("[ECBM] frame was sent in ${swatch.elapsed.inMilliseconds} ms");
    sleep(transferSendReceiveDelay);
    swatch.reset();
    var frame = await _receiveFrame(
        waitTimeout: waitTimeout, receiveTimeout: receiveTimeout);
    print("[ECBM] frame was received in ${swatch.elapsed.inMilliseconds} ms");
    return _decodeFrame(frame);
  }

  Future<void> _sendPacket(ByteData packet) async {
    await _sendFrame(_encodeFrame(packet));
  }

  // Put Frame
  // Return Packet
  ByteData _decodeFrame(ByteData frame) {
    var ndata = frame.buffer.lengthInBytes - 2;
    var nDataAdd = ndata % 8 == 0 ? ndata ~/ 8 : ndata ~/ 8 + 1;
    var nrData = ndata - nDataAdd; // Without add bytes
    var buf = Uint8List(nrData);
    for (var i = 0; i < nrData; i++) {
      var tmp = frame.getUint8(i + 1);
      if (frame.getUint8(nrData + (i ~/ 7) + 1) & (1 << (i % 7)) != 0) {
        tmp |= _mark;
      }
      buf[i] = tmp;
    }
    return ByteData.view(buf.buffer);
  }

  // Put Packet
  // Return Frame
  ByteData _encodeFrame(ByteData packet) {
    var ndata = packet.lengthInBytes;
    var ndataAdd = ndata % 7 == 0 ? ndata ~/ 7 : ndata ~/ 7 + 1;
    var idataAdd = ndata;
    var buf = Uint8List(ndata + ndataAdd + 2);
    for (var i = 0; i < ndata; i++) {
      buf[i + 1] = packet.getUint8(i);
      if (buf[i + 1] & _mark != 0) {
        buf[idataAdd + (i ~/ 7) + 1] |= 1 << (i % 7);
        buf[i + 1] &= ~_mark;
      }
    }
    buf[0] = _beginMark;
    buf[ndata + ndataAdd + 1] = _endMark;
    return ByteData.view(buf.buffer);
  }

  Future<void> _flushRead() async {
    while ((await io.read()).buffer.lengthInBytes > 0) {}
  }

  // Put Frame
  Future<void> _sendFrame(ByteData frame) async {
    await io.write(frame);
  }

  // Return Frame
  Future<ByteData> _receiveFrame(
      {Duration? waitTimeout, Duration? receiveTimeout}) async {
    List<int> buf = <int>[];
    var swatch = Stopwatch();
    swatch.start();
    var isBegin = false;
    var tries = 0;
    waitTimeout ??= waitBeginMarkTimeout;
    receiveTimeout ??= receiveFrameBytesTimeout;
    while (true) {
      var tmp = await io.read();
      for (var i = 0; i < tmp.lengthInBytes; i++) {
        var b = tmp.getUint8(i);
        swatch.reset();
        tries = 0;
        if (isBegin) {
          if (b & _mark != 0) {
            if (b == _endMark) {
              buf.add(b);
              return ByteData.view(Uint8List.fromList(buf).buffer);
            } else {
              throw const FormatException("received not allowed mark byte");
            }
          } else {
            buf.add(b);
          }
        } else {
          if (b == _beginMark) {
            isBegin = true;
            buf.add(b);
            swatch.reset();
          }
        }
      }
      if (isBegin) {
        if (swatch.elapsed > receiveTimeout && tries > _minTries) {
          throw const FormatException(
              "timeout receive bytes or answer without end mark");
        }
      } else {
        if (swatch.elapsed > waitTimeout && tries > _minTries) {
          throw const FormatException("timeout wait begin mark");
        }
      }
      if (tmp.lengthInBytes == 0) {
        sleep(const Duration(milliseconds: 2));
        tries++;
      }
    }
  }

  ByteData? getSessionKey(int addr, [bool isStrict = false]) {
    if (addr == broadcastAddress) {
      if (isStrict) {
        throw Exception("Session key for addr $addr not found");
      }
      return null;
    }
    for (var i = 0; i < _encSessions.length; i++) {
      if (addr == _encSessions[i].addr) {
        return _encSessions[i].key;
      }
    }
    if (isStrict) {
      throw Exception("Session key for addr $addr not found");
    }
    return null;
  }
}
