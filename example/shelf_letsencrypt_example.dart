import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

void main(List<String> args) async {
  final domains = args[0]; // Domain for the HTTPS certificate.
  final domainsEmail = args[1];
  var certificatesDirectory =
      args.length > 2 ? args[2] : null; // Optional argument.

  certificatesDirectory ??=
      '/tmp/shelf-letsencrypt-example/'; // Default directory.

  final domainDelimiter = RegExp(r'\s*[;:,]\s*');
  final domainsList = domains.split(domainDelimiter);
  final domainsEmailList = domainsEmail.split(domainDelimiter);

  while (domainsEmailList.length < domainsList.length) {
    domainsEmailList.add(domainsEmailList.last);
  }

  final domainsAndEmails = Map.fromIterables(domainsList, domainsEmailList);

  // The Certificate handler, storing at `certificatesDirectory`.
  final certificatesHandler =
      CertificatesHandlerIO(Directory(certificatesDirectory));

  // The Let's Encrypt integration tool in `staging` mode:
  final letsEncrypt = LetsEncrypt(certificatesHandler);

  // `shelf` Pipeline:
  final pipeline = const Pipeline().addMiddleware(logRequests());
  final handler = pipeline.addHandler(_processRequest);

  final servers = await letsEncrypt.startSecureServer(
    handler,
    domainsAndEmails,
    loadAllHandledDomains: true,
  );

  final server = servers[0]; // HTTP Server.
  final serverSecure = servers[1]; // HTTPS Server.

  // Enable gzip:
  server.autoCompress = true;
  serverSecure.autoCompress = true;

  print('Serving at http://${server.address.host}:${server.port}');
  print('Serving at https://${serverSecure.address.host}:${serverSecure.port}');
}

Response _processRequest(Request request) =>
    Response.ok('Requested: ${request.requestedUri}');
