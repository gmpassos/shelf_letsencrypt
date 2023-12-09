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

# Usage

To use the `LetsEncrypt` class

```dart
import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

void main(List<String> args) async {
  final domainsArg = args[0]; // Domain for the HTTPS certificate.
  final domainsEmailArg = args[1];
  var certificatesDirectory =
      args.length > 2 ? args[2] : null; // Optional argument.

  certificatesDirectory ??= '/etc/letsencrypt/live'; // Default directory.

    final domains = _extractDomainsFromArgs(domainsArg,domainsEmailArg);

  // The Certificate handler, storing at `certificatesDirectory`.
  final certificatesHandler = CertificatesHandlerIO(Directory(certificatesDirectory));

  // The Let's Encrypt integration tool in `staging` mode:
  final LetsEncrypt letsEncrypt = LetsEncrypt(certificatesHandler, production: false);

  // `shelf` Pipeline:
  var pipeline = const Pipeline().addMiddleware(logRequests());
  var handler = pipeline.addHandler(_processRequest);

  var servers = await letsEncrypt.startSecureServer(
    handler,
    domains,
    port: 80,
    securePort: 443,
  );

  var server = servers[0]; // HTTP Server.
  var serverSecure = servers[1]; // HTTPS Server.

  // Enable gzip:
  server.autoCompress = true;
  serverSecure.autoCompress = true;

  print('Serving at http://${server.address.host}:${server.port}');
  print('Serving at https://${serverSecure.address.host}:${serverSecure.port}');
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

Response _processRequest(Request request) {
  return Response.ok('Requested: ${request.requestedUri}');
}
```

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

Graciliano M. Passos: [gmpassos@GitHub][github].
Brett Sutton [bsutton@GitHub][github]

[github]: https://github.com/gmpassos

## License

[Apache License - Version 2.0][apache_license]

[apache_license]: https://www.apache.org/licenses/LICENSE-2.0.txt