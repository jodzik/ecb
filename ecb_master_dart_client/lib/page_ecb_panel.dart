import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'ecbm.dart';
import 'ecbm_io_interfaces.dart';

enum IoHardwareType {
  tcp,
  serial,
}

enum OperationType {
  write,
  writeNoAnsw,
  writeAuth,
  read,
  streamOpen,
  streamClose,
  streamCloseAll,
  encBegin,
  encDrop,
  encDropAll,
  readInfo,
}

class PageEcbPanel extends StatefulWidget {
  final IoHardwareType ioHardwareType;
  final String port;

  const PageEcbPanel(
      {super.key, required this.ioHardwareType, required this.port});

  @override
  State<PageEcbPanel> createState() => _PageEcbPanelState();
}

class _PageEcbPanelState extends State<PageEcbPanel> {
  Ecbm? ecbm;
  String err = "Creating..";
  String requestErr = "";
  String answer = "";
  String answerString = "";
  String sig = "0";
  String addr = "1";
  String data = "";
  String encKey = "01 2A CB 45 03 8F 65 08 03 38 FF FB 02 C7 46 93";
  OperationType? operationType = OperationType.write;
  bool isEnc = false;
  int streamDataCounter = 0;

  Future<void> _init() async {
    try {
      if (widget.ioHardwareType == IoHardwareType.tcp) {
        var ecbmIoTcp = EcbmIoTcp(int.parse(widget.port));
        await ecbmIoTcp.connect();
        setState(() {
          ecbm = Ecbm(ecbmIoTcp);
        });
        ecbm!.setReceiveFrameBeginMarkTimeout(
            const Duration(milliseconds: 1000));
        print("Ecbm created");
      } else {
        throw PlatformException(
            code: "NotImplemented",
            message: "${widget.ioHardwareType} IO not implemented");
      }
    } catch (e) {
      setState(() {
        err = e.toString();
      });
      print("Fail to create ecbm: $err");
    }
  }

  @override
  void initState() {
    _init();
    super.initState();
  }

  @override
  void dispose() {
    ecbm?.io.dispose();
    super.dispose();
  }

  ByteData _hexToData(String text) {
    List<int> buffer = List.empty(growable: true);
    List<String> hexBytes = text.split(' ');
    for (final b in hexBytes) {
      if (b.isEmpty) {
        continue;
      }
      if (b.length == 1 && b[0] == ' ') {
        continue;
      }
      try {
        buffer.add(int.parse(b, radix: 16));
      } catch (e) {
        throw FormatException("Fail parse byte '$b': $e");
      }
    }
    return ByteData.view(Uint8List.fromList(buffer).buffer);
  }

  _setAnswer(ByteData response, [String? prefix]) {
    prefix ??= "";
    String newAnswerString = "";
    for (int i = 0; i < response.lengthInBytes; i++) {
      try {
        newAnswerString += String.fromCharCode(response.getUint8(i));
      } catch (e) {
        newAnswerString += ' ';
      }
    }
    setState(() {
      answer = "$prefix${Uint8List.view(response.buffer).toString()}";
      answerString = newAnswerString;
    });
  }

  _setWriteAnswer() {
    _setAnswer(ByteData(0), "WRITE_OK: ");
  }

  Future<void> _request() async {
    try {
      if (operationType == null) {
        requestErr = "OperationType not selected.";
        return;
      }
      if (operationType == OperationType.write) {
        await ecbm!.write(int.parse(addr), int.parse(sig), _hexToData(data),
            isEnc: isEnc);
        _setWriteAnswer();
      } else if (operationType == OperationType.writeNoAnsw) {
        await ecbm!.writeNoAnswer(
            int.parse(addr), int.parse(sig), _hexToData(data),
            isEnc: isEnc);
        _setWriteAnswer();
      } else if (operationType == OperationType.writeAuth) {
        await ecbm!
            .writeAuth(int.parse(addr), int.parse(sig), _hexToData(data));
        _setWriteAnswer();
      } else if (operationType == OperationType.read) {
        ByteData answerRaw =
            await ecbm!.read(int.parse(addr), int.parse(sig), isEnc: isEnc);
        _setAnswer(answerRaw);
      } else if (operationType == OperationType.streamOpen) {
        streamDataCounter = 0;
        await ecbm!.streamOpen(int.parse(addr), int.parse(sig),
            (ByteData data) {
          streamDataCounter += 1;
          _setAnswer(data, "Stream data $streamDataCounter: ");
        }, isEnc: isEnc);
        _setAnswer(ByteData(0), "STREAM_OPEN OK: ");
      } else if (operationType == OperationType.streamClose) {
        await ecbm!.streamClose(int.parse(addr));
        _setAnswer(ByteData(0), "STREAM_CLOSE OK: ");
      } else if (operationType == OperationType.streamCloseAll) {
        await ecbm!.streamCloseAll();
        _setAnswer(ByteData(0), "STREAM_CLOSE BROADCAST OK: ");
      } else if (operationType == OperationType.encBegin) {
        await ecbm!.beginEncSession(int.parse(addr), _hexToData(encKey));
        ByteData? sessionKey = ecbm!.getSessionKey(int.parse(addr));
        _setAnswer(sessionKey!, "ENC_OPEN OK SESSION_KEY=");
      } else if (operationType == OperationType.encDrop) {
        ecbm!.dropEncSession(int.parse(addr));
        _setAnswer(ByteData(0), "SESSION DROP OK: ");
      } else if (operationType == OperationType.encDropAll) {
        ecbm!.dropAllEncSessions();
        _setAnswer(ByteData(0), "ALL SESSION DROP OK: ");
      } else if (operationType == OperationType.readInfo) {
        var info = await ecbm!.readInfo(int.parse(addr));
        _setAnswer(ByteData(0), "INFO: $info");
      } else {
        throw Exception("NotImplemented $operationType");
      }
      setState(() {
        requestErr = "";
      });
    } catch (e) {
      setState(() {
        requestErr = e.toString();
      });
    }
  }

  Future<void> _reconnect() async {
    ecbm!.io.dispose();
    await _init();
  }

  Widget _buildOperationTypeCheckbox(OperationType operationType) {
    return SizedBox(
      height: 34,
      width: 200,
      child: ListTile(
        title: Text(operationType.name),
        leading: Radio<OperationType>(
          value: operationType,
          groupValue: this.operationType,
          onChanged: (OperationType? value) {
            setState(() {
              this.operationType = value;
            });
          },
        ),
      ),
    );
  }

  Widget _buildTextField(String title, String text, Function(String) onChange,
      {int? maxLength, List<TextInputFormatter>? formatters, int? maxLines}) {
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 10, horizontal: 40),
      child: SizedBox(
        width: maxLength == null ? 400 : 20 + maxLength * 8,
        height: maxLines == null ? 80 : 40 + maxLines * 40,
        child: TextFormField(
            maxLines: maxLines,
            initialValue: text,
            maxLength: maxLength,
            decoration: InputDecoration(labelText: title),
            onChanged: (value) => setState(() {
                  onChange(value);
                }),
            inputFormatters: formatters),
      ),
    );
  }

  Widget _buildCheckbox(String title, bool value, Function(bool) onChange) {
    return Row(
      children: [
        Text(title),
        Checkbox(
            value: value,
            onChanged: (value) => setState(() {
                  onChange(value!);
                }))
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text("ECB panel"),
      ),
      body: Center(
        child: ecbm == null
            ? Column(
                children: [
                  Text("ECBM interface not created: $err"),
                  TextButton(
                      onPressed: _reconnect, child: const Text("Reconnect"))
                ],
              )
            : Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: <Widget>[
                  TextButton(
                      onPressed: _reconnect, child: const Text("Reconnect")),
                  Row(
                    children: [
                      Column(
                        children: [
                          _buildOperationTypeCheckbox(OperationType.write),
                          _buildOperationTypeCheckbox(
                              OperationType.writeNoAnsw),
                          _buildOperationTypeCheckbox(OperationType.writeAuth),
                          _buildOperationTypeCheckbox(OperationType.read),
                        ],
                      ),
                      Column(
                        children: [
                          _buildOperationTypeCheckbox(OperationType.streamOpen),
                          _buildOperationTypeCheckbox(
                              OperationType.streamClose),
                          _buildOperationTypeCheckbox(
                              OperationType.streamCloseAll),
                        ],
                      ),
                      Column(
                        children: [
                          _buildOperationTypeCheckbox(OperationType.encBegin),
                          _buildOperationTypeCheckbox(OperationType.encDrop),
                          _buildOperationTypeCheckbox(OperationType.encDropAll),
                        ],
                      ),
                      Column(
                        children: [
                          _buildOperationTypeCheckbox(OperationType.readInfo),
                        ],
                      ),
                    ],
                  ),
                  Row(
                    children: [
                      _buildTextField("Addr: ", addr, (value) => addr = value,
                          maxLength: 3,
                          formatters: [FilteringTextInputFormatter.digitsOnly]),
                      _buildTextField("Sig: ", sig, (value) => sig = value,
                          maxLength: 5,
                          formatters: [FilteringTextInputFormatter.digitsOnly]),
                      _buildCheckbox(
                          "IsEnc: ", isEnc, (value) => isEnc = value),
                      _buildTextField(
                          "Enc key: ", encKey, (value) => encKey = value,
                          maxLength: 48),
                    ],
                  ),
                  _buildTextField("Data(hex): ", data, (value) => data = value,
                      maxLines: 3, maxLength: 100),
                  Text(
                    requestErr,
                    style: const TextStyle(color: Colors.red),
                  ),
                  Row(
                    children: [
                      const Text("Answer: "),
                      Column(
                        children: [Text(answer), Text(answerString)],
                      )
                    ],
                  ),
                  TextButton(
                      onPressed: () => _request(),
                      child: const Text("Request")),
                ],
              ),
      ),
    );
  }
}
