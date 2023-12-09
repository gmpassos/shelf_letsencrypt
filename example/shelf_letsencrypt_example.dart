import 'dart:io';

import 'package:cron/cron.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

late HttpServer server; // HTTP Server.
late HttpServer serverSecure; // HTTPS Server.

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
  final letsEncrypt = LetsEncrypt(certificatesHandler,
      production: false, port: 80, securePort: 443);

  await _startServer(letsEncrypt, domains);
  await _startRenewalService(letsEncrypt, domains, server, serverSecure);
}

Future<void> _startServer(LetsEncrypt letsEncrypt, List<Domain> domains) async {
  // `shelf` Pipeline:
  final pipeline = const Pipeline().addMiddleware(logRequests());
  final handler = pipeline.addHandler(_processRequest);

  final servers = await letsEncrypt.startServer(
    handler,
    domains,
    loadAllHandledDomains: true,
  );

  server = servers[0]; // HTTP Server.
  serverSecure = servers[1]; // HTTPS Server.

  // Enable gzip:
  server.autoCompress = true;
  serverSecure.autoCompress = true;

  print('Serving at http://${server.address.host}:${server.port}');
  print('Serving at https://${serverSecure.address.host}:${serverSecure.port}');
}

/// Check every hour if any of the certificates need to be renewed.
Future<void> _startRenewalService(LetsEncrypt letsEncrypt, List<Domain> domains,
    HttpServer server, HttpServer secureServer) async {
  Cron().schedule(
      Schedule(hours: '*/1'), // every hour
      () => refreshIfRequired(letsEncrypt, domains));
}

Future<void> refreshIfRequired(
  LetsEncrypt letsEncrypt,
  List<Domain> domains,
) async {
  print('Checking if any certificates need to be renewed');

  var restartRequired = false;

  for (final domain in domains) {
    final result =
        await letsEncrypt.checkCertificate(domain, requestCertificate: true);

    if (result.isOkRefreshed) {
      print('certificate for ${domain.name} was renewed');
      restartRequired = true;
    } else {
      print('Renewal not required');
    }
  }

  if (restartRequired) {
    // restart the servers.
    await Future.wait<void>([server.close(), serverSecure.close()]);
    await _startServer(letsEncrypt, domains);
    print('services restarted');
  }
}

/// splits the command line arguments into a list of [Domain]s
/// containing the domain name and and domain email addresses.
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
