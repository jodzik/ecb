import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'ecbm.dart';

class EcbmIoTcp implements EcbmIoInterface {
  final int tcpPort;
  Socket? _socket;
  final List<int> _readBuffer = List.empty(growable: true);
  StreamSubscription<Uint8List>? _streamSubscription;

  EcbmIoTcp(this.tcpPort);

  Future<void> connect() async {
    _socket = await Socket.connect("localhost", tcpPort)
        .timeout(const Duration(milliseconds: 1000));
    _streamSubscription = _socket!.listen((Uint8List data) {
      _readBuffer.addAll(data);
    });
  }

  @override
  Future<void> dispose() async {
    await _streamSubscription?.cancel();
    await _socket?.close();
  }

  @override
  Future<ByteData> read() async {
    var rv = ByteData.view(Uint8List.fromList(_readBuffer).buffer);
    if (rv.lengthInBytes > 0) {
      _readBuffer.clear();
    } else {
      await Future.delayed(const Duration(microseconds: 100));
    }
    return rv;
  }

  @override
  Future<void> write(ByteData data) async {
    var dataToWrite = Uint8List.view(data.buffer);
    _socket!.add(dataToWrite);
  }
}
