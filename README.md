# shelf_letsencrypt

[![pub package](https://img.shields.io/pub/v/shelf_letsencrypt.svg?logo=dart&logoColor=00b9fc)](https://pub.dev/packages/shelf_letsencrypt)
[![Null Safety](https://img.shields.io/badge/null-safety-brightgreen)](https://dart.dev/null-safety)
[![Codecov](https://img.shields.io/codecov/c/github/gmpassos/shelf_letsencrypt)](https://app.codecov.io/gh/gmpassos/shelf_letsencrypt)
[![Dart CI](https://github.com/gmpassos/shelf_letsencrypt/actions/workflows/dart.yml/badge.svg?branch=master)](https://github.com/gmpassos/shelf_letsencrypt/actions/workflows/dart.yml)
[![GitHub Tag](https://img.shields.io/github/v/tag/gmpassos/shelf_letsencrypt?logo=git&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt/releases)
[![New Commits](https://img.shields.io/github/commits-since/gmpassos/shelf_letsencrypt/latest?logo=git&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt/network)
[![Last Commits](https://img.shields.io/github/last-commit/gmpassos/shelf_letsencrypt?logo=git&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt/commits/master)
[![Pull Requests](https://img.shields.io/github/issues-pr/gmpassos/shelf_letsencrypt?logo=github&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt/pulls)
[![Code size](https://img.shields.io/github/languages/code-size/gmpassos/shelf_letsencrypt?logo=github&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt)
[![License](https://img.shields.io/github/license/gmpassos/shelf_letsencrypt?logo=open-source-initiative&logoColor=green)](https://github.com/gmpassos/shelf_letsencrypt/blob/master/LICENSE)

`shelf_letsencrypt` brings support for [Let's Encrypt][letsencrypt] to the [shelf][shelf_package] package.

[shelf_package]: https://pub.dev/packages/shelf

[letsencrypt]: https://letsencrypt.org/

# Developing with shelf_letsencrypt
LetsEncrypt provide a few challenges for your development enviroment. 
Read on for a few hints.

## A word of caution
LetsEncrypt rate limits the issuing of production certificates.
It is very easy to get locked out of letsencrypt for an extended period of time (days)
leaving you in the situation where you can't issue a production certificate.

CRITICAL: you could end up with your production systems down for days!!!!

I would advise you to read up on the Lets Encrypt rate limits:

https://letsencrypt.org/docs/rate-limits/

To avoid this (potentially) major issue make certain that you test with a STAGING
certificate.


You do this by passing in 'production: false' (the default) when creating
the LetsEncrypt certificate.
Staging certificates still have rate limits but they are much more generours

```dart 
final LetsEncrypt letsEncrypt = LetsEncrypt(certificatesHandler, production: false);
```


## Permissions
On Linux you need to be root (sudo) to open a port below 1024. If you try
to start your server with the default ports (80, 443) you will fail.


## NAT for your Development environment
To issue a certificate LetsEncrypt needs to be able to connect to your
webserver on port 80.
This will work fine in production (with the write firewall rules) but in 
a development environment can be a bit tricky.

The above Permission limitations add to the complication. 

The easist way to do this is (for dev):
1) start your server on ports 8080 and 8443 (or any pair above 1024)
2) set up two NATS on your router that forward ports to your dev machine.
   80 -> 8080
   443 -> 8443


## DNS for development
For Lets Encrypt to issue a certificate it must be able to resolve the domain
name of the certificate that you are requesting.

To avoid tampering with your production DNS I keep a cheap domain name that I 
use in test. 
I then use cloudflare's free DNS hosting service to host the domain name which
allows me to add the necessary A record which points to my WFH router on which
I've configured the above NAT.

## Multi-Domain Support
Starting with `shelf_letsencrypt: 2.0.0`, support for multiple domains on the same HTTPS port has been introduced. This
enhancement allows `shelf_letsencrypt` to manage certificate requests and automatically serve multiple domains
seamlessly.

This functionality is powered by the [multi_domain_secure_server][pub_multi_domain_secure_server] package (developed
by [gmpassos][github_gmpassos]), specifically created for `shelf_letsencrypt`. It enables a `SecureServerSocket` to handle
different `SecurityContext` (certificates) on the same listening port. For more details, check out the source code
on [GitHub][github_multi_domain_secure_server].

[pub_multi_domain_secure_server]: https://pub.dev/packages/multi_domain_secure_server
[github_multi_domain_secure_server]: https://github.com/gmpassos/multi_domain_secure_server

# Usage

To use the `LetsEncrypt` class

```dart
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

```

## Renewals

Each time your call startServer it will check if any certificates need to
be renewed in the next 5 days (or if they are expired) and renew the
certificate.

This however isn't sufficient for any long running service.

The example includes a renewal service that does a daily check if any certificate
need renewing.
If a cert needs to be renewed, it will renew it and then gracefully restart
the server with the new certs.

## Source

The official source code is [hosted @ GitHub][github_shelf_letsencrypt]:

- https://github.com/gmpassos/shelf_letsencrypt

[github_shelf_letsencrypt]: https://github.com/gmpassos/shelf_letsencrypt

# Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/gmpassos/shelf_letsencrypt/issues

# Contribution

Any help from the open-source community is always welcome and needed:

- Found an issue?
    - Please fill a bug report with details.
- Wish a feature?
    - Open a feature request with use cases.
- Are you using and liking the project?
    - Promote the project: create an article, do a post or make a donation.
- Are you a developer?
    - Fix a bug and send a pull request.
    - Implement a new feature.
    - Improve the Unit Tests.
- Have you already helped in any way?
    - **Many thanks from me, the contributors and everybody that uses this project!**

*If you donate 1 hour of your time, you can contribute a lot, because others will do the same, just be part and start
with your 1 hour.*

# TODO

- Add support for multiple HTTPS domains and certificates.
- Add helper to generate self-signed certificates (for local tests).

# Author

Graciliano M. Passos: [gmpassos@GitHub][github_gmpassos].
Brett Sutton [bsutton@GitHub][github_bsutton]

[github_gmpassos]: https://github.com/gmpassos
[github_bsutton]: https://github.com/bsutton

## Sponsor

Don't be shy, show some love, and become our GitHub Sponsor ([gmpassos][sponsor_gmpassos], [bsutton][sponsor_bsutton]).
Your support means the world to us, and it keeps the code caffeinated! ☕✨

Thanks a million! 🚀😄

[sponsor_gmpassos]: https://github.com/sponsors/gmpassos
[sponsor_bsutton]: https://github.com/sponsors/bsutton

## License

[Apache License - Version 2.0][apache_license]

[apache_license]: https://www.apache.org/licenses/LICENSE-2.0.txt