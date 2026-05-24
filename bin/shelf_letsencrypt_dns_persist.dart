import 'dart:io';

import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

Future<void> main(List<String> args) async {
  final options = _CliOptions.parse(args);
  if (options == null) {
    _printUsage(stderr);
    exitCode = 64;
    return;
  }

  final certificatesHandler = CertificatesHandlerIO(
    Directory(options.certificatesDirectory),
  );
  final letsEncrypt = LetsEncrypt(
    certificatesHandler,
    challengeType: LetsEncryptChallengeType.dnsPersist,
    production: options.production,
    acmeDirectoryUrl: options.acmeDirectoryUrl,
  );

  final pending = await letsEncrypt.prepareDnsPersistCertificateRequest(
    Domain(name: options.domain, email: options.email),
  );

  stdout.writeln('Publish this TXT record before continuing:\n');
  stdout.writeln('Host : ${pending.proof.txtRecordName}');
  stdout.writeln('Value: ${pending.proof.txtRecordValue}');
  stdout.writeln('');
  stdout.writeln('BIND: ${pending.proof.toBindString()}');
  stdout.writeln('');

  if (!options.autoContinue) {
    stdout.writeln(
      'Press ENTER after the TXT record is published and visible in DNS.',
    );
    stdin.readLineSync();
  }

  final ok = await pending.complete(
    forceRequestCertificate: options.forceRequestCertificate,
  );
  if (!ok) {
    stderr.writeln('Certificate request did not complete successfully.');
    exitCode = 1;
    return;
  }

  stdout.writeln(
    'Certificate issued and stored under ${options.certificatesDirectory}.',
  );
}

class _CliOptions {
  _CliOptions({
    required this.domain,
    required this.email,
    required this.certificatesDirectory,
    required this.production,
    required this.acmeDirectoryUrl,
    required this.autoContinue,
    required this.forceRequestCertificate,
  });

  final String domain;
  final String email;
  final String certificatesDirectory;
  final bool production;
  final String? acmeDirectoryUrl;
  final bool autoContinue;
  final bool forceRequestCertificate;

  static _CliOptions? parse(List<String> args) {
    String? domain;
    String? email;
    String certificatesDirectory = 'certs';
    String? acmeDirectoryUrl;
    var production = false;
    var autoContinue = false;
    var forceRequestCertificate = false;

    for (var i = 0; i < args.length; i++) {
      final arg = args[i];
      switch (arg) {
        case '--domain':
          domain = _nextValue(args, ++i, arg);
          break;
        case '--email':
          email = _nextValue(args, ++i, arg);
          break;
        case '--cert-dir':
          certificatesDirectory = _nextValue(args, ++i, arg) ?? 'certs';
          break;
        case '--acme-dir':
          acmeDirectoryUrl = _nextValue(args, ++i, arg);
          break;
        case '--production':
          production = true;
          break;
        case '--yes':
          autoContinue = true;
          break;
        case '--force-request-certificate':
          forceRequestCertificate = true;
          break;
        case '--help':
        case '-h':
          return null;
        default:
          stderr.writeln('Unknown argument: $arg');
          return null;
      }
    }

    if (domain == null || domain.isEmpty || email == null || email.isEmpty) {
      return null;
    }

    return _CliOptions(
      domain: domain,
      email: email,
      certificatesDirectory: certificatesDirectory,
      production: production,
      acmeDirectoryUrl: acmeDirectoryUrl,
      autoContinue: autoContinue,
      forceRequestCertificate: forceRequestCertificate,
    );
  }

  static String? _nextValue(List<String> args, int index, String option) {
    if (index >= args.length) {
      stderr.writeln('Missing value for $option');
      return null;
    }
    return args[index];
  }
}

void _printUsage(IOSink out) {
  out.writeln(
    'Usage: dart run shelf_letsencrypt_dns_persist --domain <fqdn> --email <contact>',
  );
  out.writeln('');
  out.writeln('Options:');
  out.writeln(
    '  --cert-dir <path>   Directory used by CertificatesHandlerIO. Default: certs',
  );
  out.writeln('  --acme-dir <url>    Override the ACME directory URL.');
  out.writeln(
    '  --production        Use Let\'s Encrypt production instead of staging.',
  );
  out.writeln('  --yes               Do not wait for ENTER before continuing.');
  out.writeln(
    '  --force-request-certificate  Request a certificate even if one is valid.',
  );
}
