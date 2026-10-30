import 'dart:async';
import 'dart:io';

import 'package:collection/collection.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_static/shelf_static.dart';

import '../certificates_handler_io.dart';
import '../domain.dart';
import '../letsencrypt.dart';
import 'certificate_info.dart';
import 'cli.dart';

/// `verify`: checks the certificate a live server presents.
class VerifyCommand extends CliCommand {
  VerifyCommand(super.cli) {
    argParser
      ..addOption('port', help: 'The HTTPS port.', defaultsTo: '443')
      ..addOption('connect',
          help: 'Connect to this address instead of the domain, still asking '
              'for the domain certificate (SNI). Useful behind a load '
              'balancer or before DNS changes.',
          valueHelp: 'address')
      ..addOption('days',
          help: 'Fail if the served certificate expires within this many '
              'days.',
          defaultsTo: '5')
      ..addFlag('production',
          negatable: false,
          help: 'Require a trusted certificate (default: staging, whose '
              'certificates are accepted untrusted).');
  }

  @override
  String get name => 'verify';

  @override
  String get description =>
      'Connects to the live HTTPS server of each domain and checks that it '
      'serves the stored certificate, and that it is not close to expiry.';

  @override
  String get invocation => '${runner!.executableName} $name <domain>...';

  @override
  Future<int> run() async {
    final domains = domainArguments();
    final port = intOption('port');
    final days = intOption('days');
    final connect = argResults!.option('connect');
    final production = argResults!.flag('production');
    final handler = openHandler();
    final now = cli.clock();

    var failed = false;
    final results = <Map<String, Object?>>[];
    for (final domain in domains) {
      final stored =
          DomainCertificateStatus.read(handler, domain, renewDays: 0).info;
      final problems = <String>[];
      X509Certificate? served;
      try {
        served = await _peerCertificate(connect ?? domain, port, domain,
            acceptUntrusted: !production);
        if (served == null) problems.add('No certificate served');
      } catch (e) {
        problems.add(describeError(e));
      }

      int? daysLeft;
      bool? matchesStored;
      if (served != null) {
        daysLeft = served.endValidity.difference(now).inDays;
        if (served.endValidity.isBefore(now)) {
          problems.add('Certificate expired on ${served.endValidity.toUtc()}');
        } else if (daysLeft < days) {
          problems.add('Certificate expires in $daysLeft days');
        }
        if (stored != null) {
          matchesStored =
              const ListEquality<int>().equals(served.der, stored.der);
          if (!matchesStored) {
            problems.add('Served certificate differs from the stored one '
                '(restart the server to load it?)');
          }
        }
      }

      final ok = problems.isEmpty;
      failed |= !ok;
      results.add({
        'domain': domain,
        'ok': ok,
        if (served != null) 'notAfter': served.endValidity.toUtc().toString(),
        if (daysLeft != null) 'daysLeft': daysLeft,
        if (served != null) 'issuer': served.issuer,
        'matchesStored': matchesStored,
        if (!ok) 'problems': problems,
      });
      if (!json) {
        if (ok) {
          cli.out.writeln('OK    $domain: $daysLeft days left'
              '${matchesStored == null ? ' (no stored certificate)' : ', matches the stored certificate'}');
        } else {
          for (final problem in problems) {
            cli.out.writeln('FAIL  $domain: $problem');
          }
        }
      }
    }
    if (json) printJson({'domains': results});
    return failed ? 1 : 0;
  }

  static Future<X509Certificate?> _peerCertificate(
      String address, int port, String domain,
      {required bool acceptUntrusted}) async {
    final socket = await Socket.connect(address, port,
        timeout: const Duration(seconds: 15));
    SecureSocket? secure;
    try {
      secure = await SecureSocket.secure(socket,
          host: domain, onBadCertificate: (_) => acceptUntrusted);
      return secure.peerCertificate;
    } finally {
      if (secure != null) {
        secure.destroy();
      } else {
        socket.destroy();
      }
    }
  }
}

/// `serve`: an HTTPS server with automatic certificates.
class ServeCommand extends AcmeCommand {
  ServeCommand(super.cli) {
    argParser
      ..addOption('secure-port', help: 'The HTTPS port.', defaultsTo: '443')
      ..addOption('static',
          help: 'Serve the files of this directory (index.html by default). '
              'Without it, every page answers "OK".',
          valueHelp: 'dir')
      ..addOption('renew-days',
          help: 'Renew certificates that expire within this many days.',
          defaultsTo: '30')
      ..addOption('renew-interval',
          help: 'How often to check for renewals, e.g. 12h, 30m or 1d.',
          defaultsTo: '12h');
  }

  @override
  String get name => 'serve';

  @override
  String get description =>
      'Runs an HTTPS server for the domains, requesting and renewing their '
      'certificates. Stops on Ctrl-C or SIGTERM.';

  @override
  String get invocation =>
      '${runner!.executableName} $name <domain>... --email <email>';

  @override
  Future<int> run() async {
    final names = domainArguments();
    final contact = email;
    final domains = [
      for (final name in names) Domain(name: name, email: contact)
    ];
    final renewDays = intOption('renew-days');
    final interval = _duration(argResults!.option('renew-interval')!);
    final securePort = intOption('secure-port');

    final staticDir = argResults!.option('static');
    if (staticDir != null && !Directory(staticDir).existsSync()) {
      usageException('--static is not a directory: $staticDir');
    }
    final Handler app = staticDir == null
        ? (_) => Response.ok('OK\n')
        : createStaticHandler(staticDir, defaultDocument: 'index.html');

    final handler = openHandler();
    final letsEncrypt = createLetsEncrypt(handler, securePort: securePort);

    var servers = await letsEncrypt.startServer(app, domains);
    cli.out.writeln(
        'Serving ${names.map((e) => 'https://$e:$securePort/').join(' ')}'
        ' (HTTP on ${letsEncrypt.port})');

    var renewing = false;
    Future<void> renewDue() async {
      if (renewing) return;
      renewing = true;
      try {
        servers = await _renewDue(
            letsEncrypt, handler, app, domains, servers, renewDays);
      } finally {
        renewing = false;
      }
    }

    final timer = Timer.periodic(interval, (_) => renewDue());
    try {
      await cli.waitForShutdown();
    } finally {
      timer.cancel();
      await servers.http.close(force: true);
      await servers.https.close(force: true);
    }
    cli.out.writeln('Stopped');
    return 0;
  }

  /// Renews the due certificates while the HTTP server answers the challenges,
  /// then restarts the servers to load them.
  Future<({HttpServer http, HttpServer https})> _renewDue(
      LetsEncrypt letsEncrypt,
      CertificatesHandlerIO handler,
      Handler app,
      List<Domain> domains,
      ({HttpServer http, HttpServer https}) servers,
      int renewDays) async {
    var renewed = false;
    for (final domain in domains) {
      final status = DomainCertificateStatus.read(handler, domain.name,
          renewDays: renewDays);
      if (!status.isDue) continue;
      try {
        if (await letsEncrypt.requestCertificate(domain)) {
          renewed = true;
          cli.out.writeln('renewed   ${domain.name}');
        }
      } catch (e) {
        cli.err.writeln('FAIL  renewing ${domain.name}: ${describeError(e)}');
      }
    }
    if (!renewed) return servers;

    await servers.http.close(force: true);
    await servers.https.close(force: true);
    return letsEncrypt.startServer(app, domains,
        checkCertificate: false, requestCertificate: false);
  }

  Duration _duration(String value) {
    final match = RegExp(r'^(\d+)([smhd])$').firstMatch(value);
    final amount = match == null ? 0 : int.parse(match[1]!);
    if (amount <= 0) {
      usageException('--renew-interval must be like 30s, 15m, 12h or 1d: '
          '$value');
    }
    return switch (match![2]) {
      's' => Duration(seconds: amount),
      'm' => Duration(minutes: amount),
      'h' => Duration(hours: amount),
      _ => Duration(days: amount),
    };
  }
}
