import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';

import '../certificates_handler_io.dart';
import '../certs_handler.dart';
import '../domain.dart';
import '../letsencrypt.dart';
import '../logging.dart';
import 'acme_commands.dart';
import 'server_commands.dart';
import 'storage_commands.dart';

/// Creates the [LetsEncrypt] used by the commands that talk to an ACME server.
typedef LetsEncryptFactory = LetsEncrypt Function(
    CertificatesHandler certificatesHandler,
    {required int port,
    required int securePort,
    required String bindingAddress,
    required bool production,
    Logging? log});

/// The `shelf_letsencrypt` command-line tool.
///
/// Exit codes: `0` success, `1` failure, `64` usage error.
class ShelfLetsEncryptCli {
  ShelfLetsEncryptCli(
      {StringSink? out,
      StringSink? err,
      LetsEncryptFactory? letsEncrypt,
      Future<void> Function()? waitForShutdown,
      DateTime Function()? clock})
      : out = out ?? stdout,
        err = err ?? stderr,
        letsEncrypt = letsEncrypt ?? _defaultLetsEncrypt,
        waitForShutdown = waitForShutdown ?? _waitForSignal,
        clock = clock ?? DateTime.now;

  /// The environment variable used when `--dir` is not given.
  static const dirEnvironmentVariable = 'SHELF_LETSENCRYPT_DIR';

  final StringSink out;
  final StringSink err;
  final LetsEncryptFactory letsEncrypt;

  /// Completes when `serve` should stop. Defaults to `SIGINT` or `SIGTERM`.
  final Future<void> Function() waitForShutdown;
  final DateTime Function() clock;

  late final CommandRunner<int> runner = _Runner(this)
    ..argParser.addOption('dir',
        abbr: 'd',
        help: 'The certificates directory '
            '(default: \$$dirEnvironmentVariable).',
        valueHelp: 'path')
    ..argParser.addOption('account-dir',
        help: 'The account directory name.',
        defaultsTo: CertificatesHandler.defaultAccountDirectoryName)
    ..argParser.addOption('private-key-file',
        help: 'The private key file name.',
        defaultsTo: CertificatesHandler.defaultPrivateKeyPEMFileName)
    ..argParser.addOption('public-key-file',
        help: 'The public key file name.',
        defaultsTo: CertificatesHandler.defaultPublicKeyPEMFileName)
    ..argParser.addOption('fullchain-file',
        help: 'The certificate chain file name.',
        defaultsTo: CertificatesHandler.defaultFullChainPEMFileName)
    ..argParser
        .addFlag('json', negatable: false, help: 'Print the result as JSON.')
    ..argParser.addFlag('verbose',
        abbr: 'v', negatable: false, help: 'Print the library log to stderr.')
    ..addCommand(CheckCommand(this))
    ..addCommand(ListCommand(this))
    ..addCommand(ShowCommand(this))
    ..addCommand(RequestCommand(this, renew: false))
    ..addCommand(RequestCommand(this, renew: true))
    ..addCommand(RotateKeyCommand(this))
    ..addCommand(VerifyCommand(this))
    ..addCommand(ServeCommand(this));

  /// Runs the command in [args] and returns the exit code.
  Future<int> run(List<String> args) async {
    try {
      return await runner.run(args) ?? 0;
    } on UsageException catch (e) {
      err.writeln(e);
      return 64;
    } on FileSystemException catch (e) {
      err.writeln('FAIL  ${describeError(e)}');
      return 1;
    }
  }

  static LetsEncrypt _defaultLetsEncrypt(
          CertificatesHandler certificatesHandler,
          {required int port,
          required int securePort,
          required String bindingAddress,
          required bool production,
          Logging? log}) =>
      LetsEncrypt(certificatesHandler,
          port: port,
          securePort: securePort,
          bindingAddress: bindingAddress,
          production: production,
          log: log);

  static Future<void> _waitForSignal() {
    final stop = Completer<void>();
    final subscriptions = [
      ProcessSignal.sigint,
      if (!Platform.isWindows) ProcessSignal.sigterm
    ].map((signal) => signal.watch().listen((_) {
          if (!stop.isCompleted) stop.complete();
        }));
    final active = subscriptions.toList();
    return stop.future.whenComplete(() {
      for (final subscription in active) {
        subscription.cancel();
      }
    });
  }
}

/// Prints its usage to [ShelfLetsEncryptCli.out] instead of `print`.
class _Runner extends CommandRunner<int> {
  _Runner(this.cli)
      : super('shelf_letsencrypt',
            "Manages the Let's Encrypt certificates of shelf_letsencrypt.");

  final ShelfLetsEncryptCli cli;

  @override
  void printUsage() => cli.out.writeln(usage);
}

/// A one-line description of [error] for the user.
String describeError(Object error) => switch (error) {
      FileSystemException(:final message, :final path?) => '$message: $path',
      FileSystemException(:final message) => message,
      StateError(:final message) => message,
      ArgumentError(:final message) => '$message',
      SocketException(:final message, :final osError?) =>
        '$message (${osError.message})',
      SocketException(:final message) => message,
      HandshakeException(:final message) => 'TLS handshake failed: $message',
      _ => '$error',
    };

/// The options and helpers shared by every command.
abstract class CliCommand extends Command<int> {
  CliCommand(this.cli);

  final ShelfLetsEncryptCli cli;

  @override
  void printUsage() => cli.out.writeln(usage);

  bool get json => globalResults!.flag('json');
  bool get verbose => globalResults!.flag('verbose');

  /// The certificates directory from `--dir` or the environment.
  String get directoryPath {
    final dir = globalResults!.option('dir') ??
        Platform.environment[ShelfLetsEncryptCli.dirEnvironmentVariable];
    if (dir == null || dir.isEmpty) {
      usageException('Missing --dir '
          '(or \$${ShelfLetsEncryptCli.dirEnvironmentVariable}).');
    }
    return dir;
  }

  String get _accountDirectory => globalResults!.option('account-dir')!;
  String get _privateKeyFile => globalResults!.option('private-key-file')!;
  String get _publicKeyFile => globalResults!.option('public-key-file')!;
  String get _fullChainFile => globalResults!.option('fullchain-file')!;

  /// Opens the certificates directory like the server does: it is created if
  /// missing and an older store is set to owner-only permissions.
  CertificatesHandlerIO openHandler() =>
      CertificatesHandlerIO(Directory(directoryPath),
          accountDirectory: _accountDirectory,
          privateKeyPEMFileName: _privateKeyFile,
          publicKeyPEMFileName: _publicKeyFile,
          fullChainPEMFileName: _fullChainFile);

  /// See [CertificatesHandlerIO.inspectStorage].
  List<String> inspectStorage() =>
      CertificatesHandlerIO.inspectStorage(Directory(directoryPath),
          accountDirectory: _accountDirectory,
          privateKeyPEMFileName: _privateKeyFile,
          publicKeyPEMFileName: _publicKeyFile,
          fullChainPEMFileName: _fullChainFile);

  /// Forwards the library log to stderr with `--verbose`.
  Logging get log => (level, message, error, stackTrace) {
        if (!verbose) return;
        cli.err.writeln(
            '[$level] ${message ?? ''}${error == null ? '' : ' $error'}');
      };

  /// The domain names in the command arguments, lower-cased.
  List<String> domainArguments({bool required = true}) {
    final names = argResults!.rest.map((e) => e.toLowerCase()).toList();
    if (required && names.isEmpty) usageException('Missing <domain>.');
    for (final name in names) {
      if (!Domain(name: name, email: '').isValidName) {
        usageException('Invalid domain name: $name');
      }
    }
    return names;
  }

  int intOption(String name) {
    final value = argResults!.option(name)!;
    final parsed = int.tryParse(value);
    if (parsed == null || parsed < 0) {
      usageException('--$name must be a non-negative integer: $value');
    }
    return parsed;
  }

  void printJson(Object? value) =>
      cli.out.writeln(const JsonEncoder.withIndent('  ').convert(value));
}

/// A command that obtains certificates from Let's Encrypt.
abstract class AcmeCommand extends CliCommand {
  AcmeCommand(super.cli) {
    argParser
      ..addOption('email',
          help: 'The contact email of the ACME account.', valueHelp: 'email')
      ..addFlag('production',
          negatable: false,
          help: "Use the production Let's Encrypt API "
              '(default: staging, whose certificates are not trusted).')
      ..addOption('port',
          help: 'The HTTP port for the HTTP-01 challenge. '
              "Let's Encrypt always connects to port 80.",
          defaultsTo: '80')
      ..addOption('bind',
          help: 'The address to listen on.', defaultsTo: '0.0.0.0');
  }

  String get email {
    final email = argResults!.option('email');
    if (email == null || email.isEmpty) usageException('Missing --email.');
    return email;
  }

  bool get production => argResults!.flag('production');

  LetsEncrypt createLetsEncrypt(CertificatesHandler handler,
          {int securePort = 443}) =>
      cli.letsEncrypt(handler,
          port: intOption('port'),
          securePort: securePort,
          bindingAddress: argResults!.option('bind')!,
          production: production,
          log: log);

  /// Serves the HTTP-01 challenges of [letsEncrypt] on its port.
  Future<HttpServer> serveChallenges(LetsEncrypt letsEncrypt) =>
      serve((Request request) {
        final path = request.requestedUri.path;
        if (LetsEncrypt.isACMEPath(path)) {
          return letsEncrypt.processACMEChallengeRequest(request);
        }
        if (LetsEncrypt.isSelfCheckPath(path)) {
          return letsEncrypt.processSelfCheckRequest(request);
        }
        return Response.notFound(null);
      }, letsEncrypt.bindingAddress, letsEncrypt.port);
}
