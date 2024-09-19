import 'package:ecb_master_dart_client/page_ecb_panel.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class PageChooseIo extends StatefulWidget {
  const PageChooseIo({super.key});

  @override
  State<PageChooseIo> createState() => _PageChooseIoState();
}

class _PageChooseIoState extends State<PageChooseIo> {
  String _tcp_port = "25001";
  String _serial_port = "COM1";
  bool _is_tcp_selected = true;
  bool _is_serial_selected = false;

  void _toEcbPanel() {
    IoHardwareType ioHardwareType = IoHardwareType.tcp;
    String port = _tcp_port;
    if (_is_serial_selected) {
      ioHardwareType = IoHardwareType.serial;
      port = _serial_port;
    }
    Navigator.push(
      context,
      MaterialPageRoute(
          builder: (context) => PageEcbPanel(
                ioHardwareType: ioHardwareType,
                port: port,
              )),
    );
  }

  Widget _buildInterfaces() {
    return Row(
      children: [
        Row(
          children: [
            const Text("TCP"),
            Checkbox(
                value: _is_tcp_selected,
                onChanged: (state) => setState(() {
                      _is_tcp_selected = state!;
                      if (_is_tcp_selected) {
                        _is_serial_selected = false;
                      }
                    }))
          ],
        ),
        Row(
          children: [
            const Text("Serial"),
            Checkbox(
                value: _is_serial_selected,
                onChanged: (state) => setState(() {
                      _is_serial_selected = state!;
                      if (_is_serial_selected) {
                        _is_tcp_selected = false;
                      }
                    }))
          ],
        ),
      ],
    );
  }

  Widget _buildTcpSettings() {
    return Column(
      children: [
        TextField(
            controller: TextEditingController(text: _tcp_port),
            maxLength: 5,
            decoration:
                const InputDecoration(labelText: "TCP port(1..65535): "),
            onChanged: (value) => setState(() {
                  _tcp_port = value;
                }),
            keyboardType: TextInputType.number,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly]),
      ],
    );
  }

  Widget _buildSerialSettings() {
    return Column(
      children: [
        TextField(
            controller: TextEditingController(text: _serial_port),
            maxLength: 5,
            decoration: const InputDecoration(labelText: "Serial port(COMx): "),
            onChanged: (value) => setState(() {
                  _serial_port = value;
                }),
            keyboardType: TextInputType.number,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly]),
      ],
    );
  }

  Widget _buildInterfaceSettings() {
    if (_is_tcp_selected) {
      return _buildTcpSettings();
    } else if (_is_serial_selected) {
      return _buildSerialSettings();
    } else {
      return const Column();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text("Choose IO"),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            _buildInterfaces(),
            _buildInterfaceSettings(),
            TextButton(
              onPressed:
                  _is_tcp_selected || _is_serial_selected ? _toEcbPanel : null,
              child: const Text("To ECB panel"),
            )
          ],
        ),
      ),
    );
  }
}
