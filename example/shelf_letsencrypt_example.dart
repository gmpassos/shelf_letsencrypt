import 'dart:io';

import 'package:cron/cron.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

/// Start the example with a list of domains and a reciprocal
/// e-mail address for the domain admin:
/// ```dart
/// dart shelf_letsencrypt_example.dart \
///     www.domain.com:www2.domain.com \
///     info@domain.com:info2@domain.com
/// ```
void main(List<String> args) async {
  final domainNamesArg = args[0]; // Domains for the HTTPS certificate.
  final domainEmailsArg = args[1]; // The domains e-mail.

  var certificatesDirectory = args.length > 2
      ? args[2] // Optional argument.
      : '/tmp/shelf-letsencrypt-example/'; // Default directory.

  final domains =
      Domain.fromDomainsNamesAndEmailsArgs(domainNamesArg, domainEmailsArg);

  // The Certificate handler, storing at `certificatesDirectory`.
  final certificatesHandler =
      CertificatesHandlerIO(Directory(certificatesDirectory));

  // The Let's Encrypt integration tool in `staging` mode:
  final letsEncrypt = LetsEncrypt(
    certificatesHandler,
    production: false, // If `true` uses Let's Encrypt production API.
    port: 80,
    securePort: 443,
  );

  var servers = await _startServer(letsEncrypt, domains);

  await _startRenewalService(letsEncrypt, domains, servers.http, servers.https);
}

Future<({HttpServer http, HttpServer https})> _startServer(
    LetsEncrypt letsEncrypt, List<Domain> domains) async {
  // Build `shelf` Pipeline:
  final pipeline = const Pipeline().addMiddleware(logRequests());
  final handler = pipeline.addHandler(_processRequest);

  // Start the HTTP and HTTPS servers:
  final servers = await letsEncrypt.startServer(
    handler,
    domains,
    loadAllHandledDomains: true,
  );

  var server = servers.http; // HTTP Server.
  var serverSecure = servers.https; // HTTPS Server.

  // Enable gzip:
  server.autoCompress = true;
  serverSecure.autoCompress = true;

  print('Serving at http://${server.address.host}:${server.port}');
  print('Serving at https://${serverSecure.address.host}:${serverSecure.port}');

  return servers;
}

/// Check every hour if any of the certificates need to be renewed.
Future<void> _startRenewalService(LetsEncrypt letsEncrypt, List<Domain> domains,
    HttpServer server, HttpServer secureServer) async {
  Cron().schedule(
      Schedule(hours: '*/1'), // every hour
      () => refreshIfRequired(letsEncrypt, domains, server, secureServer));
}

Future<void> refreshIfRequired(
  LetsEncrypt letsEncrypt,
  List<Domain> domains,
  HttpServer server,
  HttpServer secureServer,
) async {
  print('-- Checking if any certificates need to be renewed');

  var restartRequired = false;

  for (final domain in domains) {
    final result =
        await letsEncrypt.checkCertificate(domain, requestCertificate: true);

    if (result.isOkRefreshed) {
      print('** Certificate for ${domain.name} was renewed');
      restartRequired = true;
    } else {
      print('-- Renewal not required');
    }
  }

  if (restartRequired) {
    // Restart the servers:
    await Future.wait<void>([server.close(), secureServer.close()]);
    await _startServer(letsEncrypt, domains);
    print('** Services restarted');
  }
}

Response _processRequest(Request request) =>
    Response.ok('Requested: ${request.requestedUri}');
