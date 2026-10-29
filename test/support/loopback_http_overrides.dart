import 'dart:io';
import 'dart:math';

/// Routes every [HttpClient] connection to the loopback interface, keeping the
/// requested host for the `Host` header and TLS SNI. Tests can then use real
/// domain names, with servers bound to `127.0.0.1`, without DNS.
///
/// TLS certificates are not verified: the servers use test certificates.
class LoopbackHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) =>
      super.createHttpClient(context)..connectionFactory = _connect;

  static Future<ConnectionTask<Socket>> _connect(
      Uri url, String? proxyHost, int? proxyPort) async {
    final task =
        await Socket.startConnect(InternetAddress.loopbackIPv4, url.port);
    if (url.scheme != 'https') return task;

    return ConnectionTask.fromSocket(
        task.socket.then((socket) => SecureSocket.secure(socket,
            host: url.host, onBadCertificate: (_) => true)),
        task.cancel);
  }
}

final _random = Random();

/// Returns a free TCP port on the loopback interface.
///
/// It is chosen below the ephemeral range (from 32768 on Linux, 49152 on
/// macOS and Windows), so that outgoing connections can't take it as their
/// source port while a test closes and binds it again.
Future<int> freePort() async {
  while (true) {
    final port = 20000 + _random.nextInt(10000);
    try {
      final socket =
          await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
      await socket.close();
      return port;
    } on SocketException {
      // In use: try another one.
    }
  }
}
