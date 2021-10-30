import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

void main(List<String> args) async {
  var domains = args[0]; // Domain for the HTTPS certificate.
  var domainsEmail = args[1];
  var certificatesDirectory =
      args.length > 2 ? args[2] : null; // Optional argument.

  certificatesDirectory ??=
      '/tmp/shelf-letsencrypt-example/'; // Default directory.

  var domainDelimiter = RegExp(r'\s*[;:,]\s*');
  var domainsList = domains.split(domainDelimiter);
  var domainsEmailList = domainsEmail.split(domainDelimiter);

  while (domainsEmailList.length < domainsList.length) {
    domainsEmailList.add(domainsEmailList.last);
  }

  var domainsAndEmails = Map.fromIterables(domainsList, domainsEmailList);

  // The Certificate handler, storing at `certificatesDirectory`.
  final certificatesHandler =
      CertificatesHandlerIO(Directory(certificatesDirectory));

  // The Let's Encrypt integration tool in `staging` mode:
  final LetsEncrypt letsEncrypt =
      LetsEncrypt(certificatesHandler, production: false);

  // `shelf` Pipeline:
  var pipeline = const Pipeline().addMiddleware(logRequests());
  var handler = pipeline.addHandler(_processRequest);

  var servers = await letsEncrypt.startSecureServer(
    handler,
    domainsAndEmails,
    port: 80,
    securePort: 443,
    loadAllHandledDomains: true,
  );

  var server = servers[0]; // HTTP Server.
  var serverSecure = servers[1]; // HTTPS Server.

  // Enable gzip:
  server.autoCompress = true;
  serverSecure.autoCompress = true;

  print('Serving at http://${server.address.host}:${server.port}');
  print('Serving at https://${serverSecure.address.host}:${serverSecure.port}');
}

Response _processRequest(Request request) {
  return Response.ok('Requested: ${request.requestedUri}');
}
