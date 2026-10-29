import 'dart:io';

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

/// Returns a free TCP port on the loopback interface.
Future<int> freePort() async {
  final socket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  await socket.close();
  return port;
}
