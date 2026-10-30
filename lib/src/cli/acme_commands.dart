import 'dart:io';

import '../certificates_handler_io.dart';
import '../domain.dart';
import 'certificate_info.dart';
import 'cli.dart';

/// `request` and `renew`: obtain certificates that are missing or expiring.
class RequestCommand extends AcmeCommand {
  RequestCommand(super.cli, {required this.renew}) {
    argParser
      ..addFlag('force',
          negatable: false,
          help: 'Request even if the current certificate is still valid. '
              "Mind Let's Encrypt's rate limits.")
      ..addOption('days',
          help: '${renew ? 'Renew' : 'Request'} certificates that expire '
              'within this many days.',
          defaultsTo: '30');
    if (renew) {
      argParser
        ..addFlag('dry-run',
            negatable: false,
            help: 'Only list the certificates that would be renewed.')
        ..addOption('pre-hook',
            help: 'A shell command to run before renewing, when a '
                'certificate is due: e.g. stop a server that holds the HTTP '
                'port. The post-hook then runs even if the renewal fails.',
            valueHelp: 'command')
        ..addOption('post-hook',
            help: 'A shell command to run after a certificate is renewed, '
                'e.g. to restart the server so it loads the new certificate.',
            valueHelp: 'command');
    }
  }

  final bool renew;

  @override
  String get name => renew ? 'renew' : 'request';

  @override
  String get description => renew
      ? 'Renews the certificates that expire within --days (all stored '
          'domains by default). Suited to cron: exits 1 if a renewal fails.'
      : 'Requests certificates for domains that have none, or whose '
          'certificate expires within --days. Answers the HTTP-01 challenge '
          'itself, so the port must be free.';

  @override
  String get invocation => renew
      ? '${runner!.executableName} $name [<domain>...] --email <email>'
      : '${runner!.executableName} $name <domain>... --email <email>';

  @override
  Future<int> run() async {
    final handler = openHandler();
    final names = renew && argResults!.rest.isEmpty
        ? (handler.listDomains()..sort())
        : domainArguments();
    final force = argResults!.flag('force');
    final days = intOption('days');
    final dryRun = renew && argResults!.flag('dry-run');
    final contact = dryRun ? '' : email;

    final results = <Map<String, Object?>>[];
    void report(String domain, String result, {String? detail, String? error}) {
      results.add({
        'domain': domain,
        'result': result,
        if (detail != null) 'detail': detail,
        if (error != null) 'error': error,
      });
      if (!json) {
        final label = result == 'failed' ? 'FAIL ' : result.padRight(9);
        cli.out.writeln(
            '$label $domain${detail == null ? '' : ': $detail'}${error == null ? '' : ': $error'}');
      }
    }

    final now = cli.clock();
    final due = <String>[];
    for (final name in names) {
      final status =
          DomainCertificateStatus.read(handler, name, renewDays: days);
      if (force || status.isDue) {
        due.add(name);
      } else {
        report(name, 'skipped',
            detail: 'valid for ${status.info!.daysLeft(now)} days'
                '${renew ? '' : ' (use --force to request anyway)'}');
      }
    }

    if (dryRun) {
      for (final name in due) {
        report(name, 'due');
      }
      if (json) printJson({'dryRun': true, 'domains': results});
      return 0;
    }

    final preHook = renew ? argResults!.option('pre-hook') : null;
    final postHook = renew ? argResults!.option('post-hook') : null;
    final hooks = <String, Map<String, Object?>>{};
    var failed = false;
    if (due.isNotEmpty) {
      if (preHook != null) {
        hooks['preHook'] = await _runHook('pre-hook', preHook);
      }
      if (hooks['preHook']?['exitCode'] case final int code when code != 0) {
        failed = true;
        for (final name in due) {
          report(name, 'failed', error: 'pre-hook failed');
        }
      } else {
        failed = !await _requestDue(handler, due, contact, report);
      }
    }

    // A pre-hook usually stops the server: the post-hook starts it again even
    // if the renewal failed.
    final renewed = results.any((e) => e['result'] == 'renewed');
    if (postHook != null && (renewed || hooks.containsKey('preHook'))) {
      hooks['postHook'] = await _runHook('post-hook', postHook);
    }
    failed |= hooks.values.any((hook) => hook['exitCode'] != 0);

    if (json) {
      printJson({'domains': results, ...hooks});
    } else if (failed && !verbose) {
      cli.err.writeln('Run with --verbose for the ACME log.');
    }
    return failed ? 1 : 0;
  }

  /// Requests a certificate for each domain in [due], answering the
  /// challenges on the HTTP port. Returns `false` if any request fails.
  Future<bool> _requestDue(
      CertificatesHandlerIO handler,
      List<String> due,
      String contact,
      void Function(String domain, String result, {String? error})
          report) async {
    final letsEncrypt = createLetsEncrypt(handler);
    final HttpServer server;
    try {
      server = await serveChallenges(letsEncrypt);
    } on SocketException catch (e) {
      for (final name in due) {
        report(name, 'failed',
            error: "Can't listen on port ${letsEncrypt.port}: "
                '${describeError(e)}');
      }
      return false;
    }
    var ok = true;
    try {
      for (final name in due) {
        try {
          if (await letsEncrypt
              .requestCertificate(Domain(name: name, email: contact))) {
            report(name, renew ? 'renewed' : 'requested');
          } else {
            ok = false;
            report(name, 'failed', error: 'Certificate not saved');
          }
        } catch (e) {
          ok = false;
          report(name, 'failed', error: describeError(e));
        }
      }
    } finally {
      await server.close(force: true);
    }
    return ok;
  }

  Future<Map<String, Object?>> _runHook(String label, String command) async {
    final result = Platform.isWindows
        ? await Process.run('cmd', ['/c', command])
        : await Process.run('sh', ['-c', command]);
    if (!json) {
      cli.out.write(result.stdout);
      cli.err.write(result.stderr);
      if (result.exitCode != 0) {
        cli.out.writeln('FAIL  $label exited with ${result.exitCode}');
      }
    }
    return {
      'command': command,
      'exitCode': result.exitCode,
      'stdout': '${result.stdout}',
      'stderr': '${result.stderr}',
    };
  }
}

/// `rotate-key`: replaces a domain key and requests a certificate for it.
class RotateKeyCommand extends AcmeCommand {
  RotateKeyCommand(super.cli);

  @override
  String get name => 'rotate-key';

  @override
  String get description =>
      'Generates a new private key for a domain and requests a certificate '
      'for it. The previous key and certificate are restored if the request '
      'fails.';

  @override
  String get invocation =>
      '${runner!.executableName} $name <domain> --email <email>';

  @override
  Future<int> run() async {
    final domains = domainArguments();
    if (domains.length != 1) usageException('Give exactly one <domain>.');
    final domain = domains.single;
    final contact = email;
    final handler = openHandler();

    final privateKey = handler.fileDomainPrivateKeyPEM(domain);
    if (!privateKey.existsSync()) {
      return _result(
          domain, false, 'No key to rotate; use `request` to create one');
    }
    // Loading the key runs the storage checks before anything is moved.
    handler.loadDomainPrivateKeyPEM(domain);

    final letsEncrypt = createLetsEncrypt(handler);
    final HttpServer server;
    try {
      server = await serveChallenges(letsEncrypt);
    } on SocketException catch (e) {
      return _result(domain, false,
          "Can't listen on port ${letsEncrypt.port}: ${describeError(e)}");
    }

    final keys = _KeyBackup(handler, domain);
    try {
      keys.moveAside();
      final ok = await letsEncrypt
          .requestCertificate(Domain(name: domain, email: contact));
      if (!ok) throw StateError('Certificate not saved');
      keys.discard();
      return _result(domain, true, null);
    } catch (e) {
      keys.restore();
      return _result(domain, false, describeError(e));
    } finally {
      await server.close(force: true);
    }
  }

  int _result(String domain, bool ok, String? error) {
    if (json) {
      printJson({
        'domain': domain,
        'rotated': ok,
        if (error != null) 'error': error,
      });
    } else if (ok) {
      cli.out.writeln('rotated   $domain: new key and certificate');
    } else {
      cli.out.writeln('FAIL  $domain: $error');
      if (!verbose) cli.err.writeln('Run with --verbose for the ACME log.');
    }
    return ok ? 0 : 1;
  }
}

/// Moves the key pair of a domain aside while a new one is requested.
class _KeyBackup {
  _KeyBackup(CertificatesHandlerIO handler, String domain)
      : _files = [
          handler.fileDomainPrivateKeyPEM(domain),
          handler.fileDomainPublicKeyPEM(domain),
        ];

  final List<File> _files;

  File _backup(File file) => File('${file.path}.previous');

  void moveAside() {
    for (final file in _files) {
      if (file.existsSync()) file.renameSync(_backup(file).path);
    }
  }

  /// Puts the previous keys back, which still match the stored certificate.
  void restore() {
    for (final file in _files) {
      final backup = _backup(file);
      if (!backup.existsSync()) continue;
      if (file.existsSync()) file.deleteSync();
      backup.renameSync(file.path);
    }
  }

  void discard() {
    for (final file in _files) {
      final backup = _backup(file);
      if (backup.existsSync()) backup.deleteSync();
    }
  }
}
