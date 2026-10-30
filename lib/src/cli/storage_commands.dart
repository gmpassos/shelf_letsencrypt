import 'dart:io';

import 'certificate_info.dart';
import 'cli.dart';

/// `check`: validates the certificates directory.
class CheckCommand extends CliCommand {
  CheckCommand(super.cli) {
    argParser.addFlag('fix',
        negatable: false,
        help: 'Apply the changes the server would make at startup: create '
            'the directory and set owner-only permissions (0700/0600).');
  }

  @override
  String get name => 'check';

  @override
  String get description =>
      'Checks the certificates directory and its keys like the server does at '
      'startup. Read-only unless --fix is given. Run it as the user the '
      'server runs as.';

  @override
  Future<int> run() async {
    final fix = argResults!.flag('fix');
    final warnings = [
      if (_runningAsRoot())
        'Running as root: the checks apply to the user that runs them, and '
            'the server must run as the owner of the directory.'
    ];

    final List<String> changes;
    try {
      changes = inspectStorage();
    } on FileSystemException catch (e) {
      if (json) {
        printJson({
          'ok': false,
          'directory': directoryPath,
          'error': e.message,
          'path': e.path,
          'warnings': warnings,
        });
      } else {
        for (final warning in warnings) {
          cli.out.writeln('warning  $warning');
        }
        cli.out.writeln('FAIL  ${describeError(e)}');
      }
      return 1;
    }

    if (fix && changes.isNotEmpty) {
      final handler = openHandler();
      handler.loadAccountPrivateKeyPEM();
      handler.listAllHandledDomains(checkSecurityContext: false);
    }

    if (json) {
      printJson({
        'ok': true,
        'directory': directoryPath,
        'changes': changes,
        'fixed': fix && changes.isNotEmpty,
        'warnings': warnings,
      });
    } else {
      for (final warning in warnings) {
        cli.out.writeln('warning  $warning');
      }
      for (final change in changes) {
        cli.out.writeln(fix ? 'fixed  $change' : 'change  $change');
      }
      if (!fix && changes.isNotEmpty) {
        cli.out.writeln('The server makes these changes at startup '
            '(or run check --fix).');
      }
      cli.out.writeln('OK    $directoryPath');
    }
    return 0;
  }

  static bool _runningAsRoot() {
    if (Platform.isWindows) return false;
    try {
      return '${Process.runSync('id', ['-u']).stdout}'.trim() == '0';
    } on ProcessException {
      return false;
    }
  }
}

/// `list`: the stored domains and when their certificates expire.
class ListCommand extends CliCommand {
  ListCommand(super.cli) {
    argParser.addOption('days',
        help: 'Certificates expiring within this many days are "expiring".',
        defaultsTo: '30');
  }

  @override
  String get name => 'list';

  @override
  String get description =>
      'Lists the stored domains and the expiry of their certificates.';

  @override
  Future<int> run() async {
    final handler = openHandler();
    final days = intOption('days');
    final now = cli.clock();
    final statuses = (handler.listDomains()..sort())
        .map((domain) =>
            DomainCertificateStatus.read(handler, domain, renewDays: days))
        .toList();

    if (json) {
      printJson({
        'directory': handler.directory.path,
        'domains': [for (final status in statuses) status.toJson(now)],
      });
      return 0;
    }

    if (statuses.isEmpty) {
      cli.out.writeln('No domains in ${handler.directory.path}');
      return 0;
    }
    final width = statuses
        .map((e) => e.domain.length)
        .fold('DOMAIN'.length, (a, b) => a > b ? a : b);
    cli.out.writeln(
        '${'DOMAIN'.padRight(width)}  EXPIRES     ${'DAYS'.padLeft(5)}  STATUS');
    for (final status in statuses) {
      final info = status.info;
      final expires =
          info == null ? '-' : _date(info.notAfter.toLocal()).padRight(10);
      final daysLeft = info == null ? '-' : '${info.daysLeft(now)}';
      cli.out.writeln('${status.domain.padRight(width)}  '
          '${expires.padRight(10)}  ${daysLeft.padLeft(5)}  '
          '${status.state.name}');
    }
    return 0;
  }
}

/// `show`: the details of a stored certificate.
class ShowCommand extends CliCommand {
  ShowCommand(super.cli) {
    argParser.addOption('days',
        help: 'Certificates expiring within this many days are "expiring".',
        defaultsTo: '30');
  }

  @override
  String get name => 'show';

  @override
  String get description =>
      'Shows a stored certificate and the files of its domain.';

  @override
  String get invocation => '${runner!.executableName} $name <domain>';

  @override
  Future<int> run() async {
    final domains = domainArguments();
    if (domains.length != 1) usageException('Give exactly one <domain>.');
    final domain = domains.single;
    final handler = openHandler();
    if (!handler.listDomains().contains(domain)) {
      cli.err.writeln('FAIL  No certificate stored for $domain');
      return 1;
    }

    final now = cli.clock();
    final status = DomainCertificateStatus.read(handler, domain,
        renewDays: intOption('days'));
    final files = {
      'privateKey': handler.fileDomainPrivateKeyPEM(domain),
      'publicKey': handler.fileDomainPublicKeyPEM(domain),
      'fullChain': handler.fileDomainFullChainPEM(domain),
    };

    if (json) {
      printJson({
        ...status.toJson(now),
        'files': {
          for (final MapEntry(:key, :value) in files.entries)
            key: {'path': value.path, 'mode': _mode(value)},
        },
      });
      return 0;
    }

    final info = status.info;
    final out = cli.out
      ..writeln('Domain:      $domain')
      ..writeln('Status:      ${status.state.name}'
          '${info == null ? '' : ' (${info.daysLeft(now)} days left)'}'
          '${status.error == null ? '' : ' - ${status.error}'}');
    if (info != null) {
      out
        ..writeln('Subject:     ${info.subject}')
        ..writeln('Names:       ${info.names.join(', ')}')
        ..writeln('Issuer:      ${info.issuer}')
        ..writeln('Valid from:  ${info.notBefore.toUtc()}')
        ..writeln('Valid until: ${info.notAfter.toUtc()}')
        ..writeln('Serial:      ${info.serialNumber.toRadixString(16)}')
        ..writeln('Chain:       ${info.chainLength} certificate(s)');
    }
    for (final MapEntry(:key, :value) in files.entries) {
      out.writeln('${'$key:'.padRight(12)} ${_mode(value) ?? 'missing'}  '
          '${value.path}');
    }
    return 0;
  }
}

String _date(DateTime time) => '${time.year.toString().padLeft(4, '0')}-'
    '${time.month.toString().padLeft(2, '0')}-'
    '${time.day.toString().padLeft(2, '0')}';

/// The permissions of [file] (e.g. `rw-------`), or `null` if it is missing.
String? _mode(File file) {
  final stat = file.statSync();
  if (stat.type == FileSystemEntityType.notFound) return null;
  return stat.modeString();
}
