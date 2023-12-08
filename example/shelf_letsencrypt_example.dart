import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';
import 'package:shelf_letsencrypt/src/certificates_handler_io.dart';

/// Start the example with a list of domains and a recipriocal
/// email address for the domain admin.
/// ```dart
/// dart shelf_letsencxrypt_example.dart \
///     www.domain.com:www2.domain.com \
///     info@domain.com:info@domain.com
/// ```
void main(List<String> args) async {
  final domainsArg = args[0]; // Domain for the HTTPS certificate.
  final domainsEmailArg = args[1];
  var certificatesDirectory =
      args.length > 2 ? args[2] : null; // Optional argument.

  certificatesDirectory ??=
      '/tmp/shelf-letsencrypt-example/'; // Default directory.

  final domains = _extractDomainsFromArgs(domainsArg, domainsEmailArg);

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
    domains,
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

/// splits the command line arguments into a list of domains
/// and domain email addresses.
List<Domain> _extractDomainsFromArgs(
    String domainsArg, String domainsEmailArg) {
  final domainDelimiter = RegExp(r'\s*[;:,]\s*');
  final domainList = domainsArg.split(domainDelimiter);
  final domainEmailList = domainsEmailArg.split(domainDelimiter);

  if (domainList.length != domainEmailList.length) {
    stderr.writeln(
        "The number of domains doesn't match the number of domain emails");
    exit(1);
  }

  final domains = <Domain>[];

  var i = 0;
  for (final domain in domainList) {
    domains.add(Domain(name: domain, email: domainEmailList[i++]));
  }
  return domains;
}

Response _processRequest(Request request) =>
    Response.ok('Requested: ${request.requestedUri}');
