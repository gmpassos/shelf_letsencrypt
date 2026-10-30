import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as pack_path;
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';
import 'package:shelf_letsencrypt/src/cli/acme_commands.dart';
import 'package:shelf_letsencrypt/src/cli/cli.dart';
import 'package:test/test.dart';

import 'support/certificates.dart';
import 'support/fake_acme_server.dart';
import 'support/loopback_http_overrides.dart';

/// Owner-only POSIX permissions are not enforced on Windows.
final _posixSkip = Platform.isWindows ? 'POSIX permissions' : null;

const _domain = 'www.example.com';
const _email = 'admin@example.com';

/// [LetsEncrypt] against a [FakeAcmeServer].
class _TestLetsEncrypt extends LetsEncrypt {
  _TestLetsEncrypt(super.certificatesHandler, this.acme,
      {required super.port,
      required super.securePort,
      required super.bindingAddress,
      required super.production,
      super.log});

  final FakeAcmeServer acme;

  @override
  String get apiBaseURL => acme.baseUrl;
}

typedef _Result = ({int code, String out, String err});

void main() {
  late Directory tmpDir;
  late String certsDir;
  late FakeAcmeServer acme;
  late int port;
  late int securePort;

  /// Stops `serve`, like a signal.
  late StreamController<ProcessSignal> shutdown;

  setUpAll(() => HttpOverrides.global = LoopbackHttpOverrides());
  tearDownAll(() => HttpOverrides.global = null);

  setUp(() async {
    tmpDir = Directory.systemTemp.createTempSync('shelf-letsencrypt-cli-');
    if (!Platform.isWindows) {
      Process.runSync('chmod', ['700', tmpDir.path]);
    }
    certsDir = pack_path.join(tmpDir.path, 'certs');
    port = await freePort();
    do {
      securePort = await freePort();
    } while (securePort == port);
    acme = FakeAcmeServer(challengePort: port);
    await acme.start();
    shutdown = StreamController<ProcessSignal>.broadcast();
  });

  tearDown(() async {
    await shutdown.close();
    await acme.close();
    tmpDir.deleteSync(recursive: true);
  });

  ShelfLetsEncryptCli cli(StringSink out, StringSink err) =>
      ShelfLetsEncryptCli(
          out: out,
          err: err,
          shutdownSignals: () => [shutdown.stream],
          letsEncrypt: (handler,
                  {required port,
                  required securePort,
                  required bindingAddress,
                  required production,
                  log}) =>
              _TestLetsEncrypt(handler, acme,
                  port: port,
                  securePort: securePort,
                  bindingAddress: bindingAddress,
                  production: production,
                  log: log));

  Future<_Result> run(List<String> args, {bool withDir = true}) async {
    final out = StringBuffer();
    final err = StringBuffer();
    final code = await cli(out, err).run([
      if (withDir) ...['--dir', certsDir],
      ...args
    ]);
    return (code: code, out: '$out', err: '$err');
  }

  /// The options that point an ACME command at the fake server.
  List<String> acmeOptions() =>
      ['--email', _email, '--port', '$port', '--bind', '127.0.0.1'];

  Future<_Result> request([List<String> extra = const []]) =>
      run(['request', _domain, ...acmeOptions(), ...extra]);

  CertificatesHandlerIO handler() => CertificatesHandlerIO(Directory(certsDir));

  Map<String, dynamic> decode(String json) =>
      jsonDecode(json) as Map<String, dynamic>;

  group('defaults', () {
    test('uses stdout, stderr and the real LetsEncrypt', () async {
      await storeSelfSignedCertificate(handler(), _domain);
      final busy = await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
      try {
        // Fails binding the challenge port, before any ACME request.
        final code = await ShelfLetsEncryptCli()
            .run(['--dir', certsDir, 'rotate-key', _domain, ...acmeOptions()]);
        expect(code, 1);
      } finally {
        await busy.close();
      }
    });

    test('stops on SIGINT, and SIGTERM except on Windows', () {
      // The test runner handles these signals itself: don't listen.
      expect(ShelfLetsEncryptCli.processShutdownSignals(),
          hasLength(Platform.isWindows ? 1 : 2));
    });

    test('waits for the first signal, then stops listening', () async {
      final sigint = StreamController<ProcessSignal>();
      final sigterm = StreamController<ProcessSignal>();
      final stopped =
          ShelfLetsEncryptCli.waitForSignals([sigint.stream, sigterm.stream]);
      expect(sigint.hasListener, isTrue);

      sigterm.add(ProcessSignal.sigterm);
      sigint.add(ProcessSignal.sigint);
      await stopped;
      expect(sigint.hasListener, isFalse);
      expect(sigterm.hasListener, isFalse);
    });

    test('describes errors in one line', () {
      expect(describeError(const FileSystemException('Denied', '/x')),
          'Denied: /x');
      expect(describeError(const FileSystemException('Denied')), 'Denied');
      expect(describeError(StateError('Broken')), 'Broken');
      expect(describeError(ArgumentError('Bad')), 'Bad');
      expect(describeError(const SocketException('Refused')), 'Refused');
      expect(describeError(TimeoutException('Slow')), contains('Slow'));
    });
  });

  group('usage', () {
    test('prints help for every command', () async {
      final top = await run(['--help'], withDir: false);
      expect(top.code, 0);
      expect(top.out, contains('Available commands:'));

      for (final command in [
        'check',
        'list',
        'show',
        'request',
        'renew',
        'rotate-key',
        'verify',
        'serve'
      ]) {
        final result = await run(['help', command], withDir: false);
        expect(result.code, 0, reason: command);
        expect(result.out, contains('Usage: shelf_letsencrypt $command'),
            reason: command);
      }
    });

    test('requires --dir', () async {
      final result = await run(['list'], withDir: false);
      expect(result.code, 64);
      expect(result.err, contains('Missing --dir'));
    });

    test('rejects an invalid domain', () async {
      final result = await run(['request', '../outside', ...acmeOptions()]);
      expect(result.code, 64);
      expect(result.err, contains('Invalid domain name'));
      expect(Directory(certsDir).listSync(), isEmpty);
    });

    test('requires --email', () async {
      final result = await run(['request', _domain]);
      expect(result.code, 64);
      expect(result.err, contains('Missing --email'));
    });

    test('rejects a non-numeric option', () async {
      final result = await run(['list', '--days', 'soon']);
      expect(result.code, 64);
    });

    test('reports a storage error', () async {
      File(certsDir).writeAsStringSync('');
      final result = await run(['list']);
      expect(result.code, 1);
      expect(result.err, startsWith('FAIL'));
    }, skip: _posixSkip);
  });

  group('check', () {
    test('is read-only', () async {
      final result = await run(['check']);
      expect(result.code, 0);
      // The reported path has symbolic links resolved (`/var` on macOS).
      // On Windows: a drive path and no POSIX mode.
      expect(
          result.out,
          matches(RegExp(
              Platform.isWindows
                  ? r'change  Create [A-Za-z]:\\.*certs$'
                  : r'change  Create /.*certs \(0700\)',
              multiLine: true)));
      expect(Directory(certsDir).existsSync(), isFalse);
    });

    test('reports and fixes an older store', () async {
      await storeSelfSignedCertificate(handler(), _domain);
      final key = handler().fileDomainPrivateKeyPEM(_domain);
      Process.runSync('chmod', ['755', certsDir]);
      Process.runSync('chmod', ['644', key.path]);

      final checked = await run(['check']);
      expect(checked.code, 0);
      expect(checked.out, contains('Set ${handler().directory.path} to 0700'));
      expect(checked.out, contains('Set ${key.path} to 0600'));
      expect(key.statSync().modeString(), 'rw-r--r--');

      final fixed = await run(['check', '--fix']);
      expect(fixed.code, 0);
      expect(fixed.out, contains('fixed  Set ${key.path} to 0600'));
      expect(key.statSync().modeString(), 'rw-------');
      expect(Directory(certsDir).statSync().modeString(), 'rwx------');

      final again = decode((await run(['--json', 'check'])).out);
      expect(again['changes'], isEmpty);
    }, skip: _posixSkip);

    test('fails under a directory writable by others', () async {
      final shared = Directory(pack_path.join(tmpDir.path, 'shared'))
        ..createSync();
      Process.runSync('chmod', ['777', shared.path]);
      certsDir = pack_path.join(shared.path, 'certs');

      final result = await run(['check']);
      expect(result.code, 1);
      expect(result.out, contains('FAIL  Storage ancestor is writable'));

      final json = decode((await run(['--json', 'check'])).out);
      expect(json['ok'], isFalse);
      expect(json['path'], endsWith('shared'));
    }, skip: _posixSkip);
  });

  group('request', () {
    test('requests, then skips a valid certificate', () async {
      final first = await request();
      expect(first.code, 0, reason: first.err);
      expect(first.out, contains('requested $_domain'));
      expect(acme.certificatesIssued, 1);

      final second = await request();
      expect(second.code, 0);
      expect(second.out, contains('skipped   $_domain: valid for'));
      expect(acme.certificatesIssued, 1);

      final forced = await request(['--force']);
      expect(forced.code, 0);
      expect(acme.certificatesIssued, 2);
    });

    test('reports a failed request', () async {
      acme.rejectNewOrder = true;
      final result = await request();
      expect(result.code, 1);
      expect(result.out, contains("FAIL  $_domain: Can't create order"));
      expect(result.err, contains('--verbose'));
    });

    test('logs the ACME client with --verbose', () async {
      final result =
          await run(['--verbose', 'request', _domain, ...acmeOptions()]);
      expect(result.code, 0);
      expect(result.err, contains('[INFO]'));
    });

    test('fails when the port is in use', () async {
      final busy = await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
      try {
        final result = await request();
        expect(result.code, 1);
        expect(result.out, contains("Can't listen on port $port"));
      } finally {
        await busy.close();
      }
    });

    test('prints JSON', () async {
      final json = decode(
          (await run(['--json', 'request', _domain, ...acmeOptions()])).out);
      expect(json['domains'], [
        {'domain': _domain, 'result': 'requested'}
      ]);
    });
  });

  group('renew', () {
    test('does nothing without due certificates', () async {
      final empty = await run(['renew', ...acmeOptions()]);
      expect(empty.code, 0);
      expect(empty.out, isEmpty);

      await request();
      final valid = await run(['renew', ...acmeOptions()]);
      expect(valid.code, 0);
      expect(valid.out, contains('skipped   $_domain: valid for'));
      expect(acme.certificatesIssued, 1);
    });

    test('lists due certificates with --dry-run', () async {
      await request();
      final result = await run(['renew', '--days', '365', '--dry-run']);
      expect(result.code, 0);
      expect(result.out, contains('due       $_domain'));
      expect(acme.certificatesIssued, 1);

      final json = decode(
          (await run(['--json', 'renew', '--days', '365', '--dry-run'])).out);
      expect(json['dryRun'], isTrue);
    });

    test('renews and runs the post-hook', () async {
      await request();
      final result = await run([
        'renew',
        '--days',
        '365',
        '--post-hook',
        'echo hooked',
        ...acmeOptions()
      ]);
      expect(result.code, 0, reason: result.err);
      expect(result.out, contains('renewed   $_domain'));
      expect(result.out, contains('hooked'));
      expect(acme.certificatesIssued, 2);
    }, skip: Platform.isWindows ? 'sh' : null);

    test('fails when the post-hook fails', () async {
      await request();
      final json = decode((await run([
        '--json',
        'renew',
        '--days',
        '365',
        '--post-hook',
        'exit 3',
        ...acmeOptions()
      ]))
          .out);
      expect((json['postHook'] as Map)['exitCode'], 3);

      final result = await run([
        'renew',
        '--days',
        '365',
        '--post-hook',
        'exit 3',
        ...acmeOptions()
      ]);
      expect(result.code, 1);
      expect(result.out, contains('post-hook exited with 3'));
    }, skip: Platform.isWindows ? 'sh' : null);

    test('runs the pre-hook before and the post-hook after', () async {
      await request();
      final result = await run([
        'renew',
        '--days',
        '365',
        '--pre-hook',
        'echo stopping',
        '--post-hook',
        'echo starting',
        ...acmeOptions()
      ]);
      expect(result.code, 0, reason: result.err);
      expect(
          result.out,
          stringContainsInOrder(
              ['stopping', 'renewed   $_domain', 'starting']));
    }, skip: Platform.isWindows ? 'sh' : null);

    test('skips the hooks when nothing is due', () async {
      await request();
      final result = await run([
        'renew',
        '--pre-hook',
        'echo stopping',
        '--post-hook',
        'echo starting',
        ...acmeOptions()
      ]);
      expect(result.code, 0);
      expect(result.out, isNot(contains('stopping')));
      expect(result.out, isNot(contains('starting')));
    }, skip: Platform.isWindows ? 'sh' : null);

    test('runs the post-hook when the pre-hook or renewal fails', () async {
      await request();
      final preFailed = decode((await run([
        '--json',
        'renew',
        '--days',
        '365',
        '--pre-hook',
        'exit 2',
        '--post-hook',
        'echo starting',
        ...acmeOptions()
      ]))
          .out);
      expect(acme.certificatesIssued, 1);
      expect((preFailed['domains'] as List).single,
          containsPair('error', 'pre-hook failed'));
      expect((preFailed['postHook'] as Map)['stdout'], 'starting\n');

      acme.rejectFinalize = true;
      final renewFailed = await run([
        'renew',
        '--days',
        '365',
        '--pre-hook',
        'true',
        '--post-hook',
        'echo starting',
        ...acmeOptions()
      ]);
      expect(renewFailed.code, 1);
      expect(renewFailed.out, contains('starting'));
    }, skip: Platform.isWindows ? 'sh' : null);

    test('does not run the post-hook when nothing is renewed', () async {
      acme.rejectFinalize = true;
      await handler().ensureDomainPEMKeyPair(_domain);
      final result =
          await run(['renew', '--post-hook', 'echo hooked', ...acmeOptions()]);
      expect(result.code, 1);
      expect(result.out, isNot(contains('hooked')));
    });
  });

  group('list and show', () {
    test('list the stored certificates', () async {
      await request();
      final h = handler();
      Directory(pack_path.join(h.directory.path, 'missing.example.com'))
          .createSync();
      await storeSelfSignedCertificate(h, 'expired.example.com', days: -1);
      await storeSelfSignedCertificate(h, 'invalid.example.com');
      h
          .fileDomainFullChainPEM('invalid.example.com')
          .writeAsStringSync('not a certificate');

      final result = await run(['list']);
      expect(result.code, 0);
      final lines = result.out.trim().split('\n');
      expect(lines.first, startsWith('DOMAIN'));
      expect(lines.skip(1).map((e) => e.split(RegExp(r'\s+')).first), [
        'expired.example.com',
        'invalid.example.com',
        'missing.example.com',
        _domain,
      ]);
      expect(result.out, matches(RegExp(r'www\.example\.com .* 8\d  ok')));

      final json = decode((await run(['--json', 'list', '--days', '365'])).out);
      final states = {
        for (final d in json['domains'] as List)
          (d as Map)['domain']: d['status']
      };
      expect(states, {
        'expired.example.com': 'expired',
        'invalid.example.com': 'invalid',
        'missing.example.com': 'missing',
        _domain: 'expiring',
      });
    });

    test('list without domains', () async {
      final result = await run(['list']);
      expect(result.out, contains('No domains'));
    });

    test('list and show do not change the directory', () async {
      expect((await run(['list'])).code, 0);
      expect((await run(['show', _domain])).code, 1);
      expect(Directory(certsDir).existsSync(), isFalse);

      await storeSelfSignedCertificate(handler(), _domain);
      final key = handler().fileDomainPrivateKeyPEM(_domain);
      Process.runSync('chmod', ['755', certsDir]);
      Process.runSync('chmod', ['644', key.path]);
      expect((await run(['list'])).code, 0);
      expect((await run(['show', _domain])).code, 0);
      expect(key.statSync().modeString(), 'rw-r--r--');
      expect(Directory(certsDir).statSync().modeString(), 'rwxr-xr-x');
    }, skip: _posixSkip);

    test('show a certificate', () async {
      await request();
      final result = await run(['show', _domain]);
      expect(result.code, 0);
      expect(result.out, contains('Status:      ok ('));
      expect(result.out, contains('Names:       $_domain'));
      expect(result.out, contains('Issuer:      Fake ACME CA'));
      if (!Platform.isWindows) {
        expect(result.out, contains('privateKey:  rw-------'));
      }

      final json = decode((await run(['--json', 'show', _domain])).out);
      expect((json['certificate'] as Map)['subject'], _domain);
      expect((json['files'] as Map).keys,
          ['privateKey', 'publicKey', 'fullChain']);
    });

    test('show an unknown domain', () async {
      final result = await run(['show', _domain]);
      expect(result.code, 1);
      expect(result.err, contains('No certificate stored'));
      expect((await run(['show'])).code, 64);
    });

    test('show an incomplete domain', () async {
      await handler().ensureDomainPEMKeyPair(_domain);
      final result = await run(['show', _domain]);
      expect(result.code, 0);
      expect(result.out, contains('Status:      missing'));
      expect(result.out, contains('missing  '));
    });
  });

  group('rotate-key', () {
    test('replaces the key and the certificate', () async {
      await request();
      final h = handler();
      final before = h.fileDomainPrivateKeyPEM(_domain).readAsStringSync();

      final result = await run(['rotate-key', _domain, ...acmeOptions()]);
      expect(result.code, 0, reason: result.err);
      expect(result.out, contains('rotated   $_domain'));
      expect(
          h.fileDomainPrivateKeyPEM(_domain).readAsStringSync(), isNot(before));
      expect(acme.certificatesIssued, 2);
      expect(h.isHandledDomainCertificate(_domain), isTrue);
      expect(
          Directory(pack_path.join(h.directory.path, _domain))
              .listSync()
              .map((e) => pack_path.basename(e.path)),
          unorderedEquals(['privkey.pem', 'pubkey.pem', 'fullchain.pem']));
    });

    test('restores the previous key when the request fails', () async {
      await request();
      final h = handler();
      final key = h.fileDomainPrivateKeyPEM(_domain).readAsStringSync();
      final chain = h.fileDomainFullChainPEM(_domain).readAsStringSync();

      acme.rejectFinalize = true;
      final result =
          await run(['--json', 'rotate-key', _domain, ...acmeOptions()]);
      expect(result.code, 1);
      expect(decode(result.out)['rotated'], isFalse);
      expect(h.fileDomainPrivateKeyPEM(_domain).readAsStringSync(), key);
      expect(h.fileDomainFullChainPEM(_domain).readAsStringSync(), chain);
      expect(h.isHandledDomainCertificate(_domain), isTrue);
      expect(
          Directory(pack_path.join(h.directory.path, _domain))
              .listSync()
              .where((e) => e.path.endsWith('.previous')),
          isEmpty);
    });

    test('fails without a key', () async {
      final result = await run(['rotate-key', _domain, ...acmeOptions()]);
      expect(result.code, 1);
      expect(result.out, contains('No key to rotate'));
    });

    test('refuses to run after an interrupted rotation', () async {
      await request();
      final key = handler().fileDomainPrivateKeyPEM(_domain);
      key.renameSync('${key.path}.previous');

      final result = await run(['rotate-key', _domain, ...acmeOptions()]);
      expect(result.code, 1);
      expect(result.out, contains('A previous rotation was interrupted'));
      expect(result.out, contains('${key.path}.previous'));
      expect(acme.certificatesIssued, 1);
    });
  });

  group('serve and verify', () {
    /// Starts `serve` and waits until it is listening.
    Future<({Future<int> code, StringBuffer out, StringBuffer err})> startServe(
        List<String> extra) async {
      final out = StringBuffer();
      final err = StringBuffer();
      final code = cli(out, err).run([
        '--dir',
        certsDir,
        'serve',
        _domain,
        ...acmeOptions(),
        '--secure-port',
        '$securePort',
        ...extra
      ]);
      final started = DateTime.now();
      while (!'$out'.contains('Serving') &&
          DateTime.now().difference(started) < const Duration(seconds: 30)) {
        if ('$err'.isNotEmpty) break;
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
      expect('$out', contains('Serving https://$_domain:$securePort/'),
          reason: '$err');
      addTearDown(() async {
        shutdown.add(ProcessSignal.sigint);
        await code;
      });
      return (code: code, out: out, err: err);
    }

    Future<String> get(String path) async {
      final client = HttpClient();
      try {
        final request =
            await client.getUrl(Uri.parse('https://$_domain:$securePort$path'));
        final response = await request.close();
        return await response.transform(utf8.decoder).join();
      } finally {
        client.close(force: true);
      }
    }

    Future<_Result> verify([List<String> extra = const []]) => run([
          'verify',
          _domain,
          '--connect',
          '127.0.0.1',
          '--port',
          '$securePort',
          ...extra
        ]);

    test('serves, verifies and stops', () async {
      final served = await startServe([]);
      expect(acme.certificatesIssued, 1);
      expect(await get('/'), 'OK\n');

      final ok = await verify();
      expect(ok.code, 0, reason: ok.out);
      expect(ok.out, contains('matches the stored certificate'));

      final expiring = await verify(['--days', '365']);
      expect(expiring.code, 1);
      expect(expiring.out, contains('Certificate expires in'));

      final untrusted = await verify(['--production']);
      expect(untrusted.code, 1);
      expect(untrusted.out, contains('TLS handshake failed'));

      shutdown.add(ProcessSignal.sigint);
      expect(await served.code, 0);
      expect('${served.out}', contains('Stopped'));
    });

    test('verify reports a stale stored certificate as a mismatch', () async {
      await startServe([]);
      handler()
          .fileDomainFullChainPEM(_domain)
          .writeAsStringSync(selfSignedCertificate(_domain).certificatePEM);

      final result = await run([
        '--json',
        'verify',
        _domain,
        '--connect',
        '127.0.0.1',
        '--port',
        '$securePort'
      ]);
      expect(result.code, 1);
      final domain = (decode(result.out)['domains'] as List).single as Map;
      expect(domain['matchesStored'], isFalse);
      expect(domain['problems'], [contains('differs from the stored one')]);
    });

    test('verify fails without a server', () async {
      final result = await verify();
      expect(result.code, 1);
      expect(result.out, startsWith('FAIL  $_domain'));
    });

    test('verify without a stored certificate', () async {
      await startServe([]);
      handler().fileDomainFullChainPEM(_domain).deleteSync();
      final result = await verify();
      expect(result.code, 0);
      expect(result.out, contains('no stored certificate'));
    });

    test('verify without --dir checks only the served certificate', () async {
      await startServe([]);
      final result = await run([
        'verify',
        _domain,
        '--connect',
        '127.0.0.1',
        '--port',
        '$securePort'
      ], withDir: false);
      expect(result.code, 0, reason: result.err);
      expect(result.out, contains('no stored certificate'));
    });

    test('serve fails cleanly when the HTTPS port is in use', () async {
      final busy =
          await ServerSocket.bind(InternetAddress.loopbackIPv4, securePort);
      try {
        final result = await run([
          'serve',
          _domain,
          ...acmeOptions(),
          '--secure-port',
          '$securePort'
        ]);
        expect(result.code, 1);
        expect(result.err, startsWith('FAIL  '));
      } finally {
        await busy.close();
      }
    });

    test('serve keeps running when a renewed certificate is unusable',
        () async {
      final served =
          await startServe(['--renew-days', '365', '--renew-interval', '1s']);
      acme.corruptCertificate = true;

      Future<void> waitFor(bool Function() condition) async {
        final started = DateTime.now();
        while (!condition() &&
            DateTime.now().difference(started) < const Duration(seconds: 30)) {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
        expect(condition(), isTrue, reason: '${served.out}\n${served.err}');
      }

      // The corrupt certificate can't be loaded: the server keeps running
      // with the previous one instead of restarting.
      await waitFor(() => '${served.err}'.contains("can't be loaded"));
      expect('${served.out}', isNot(contains('restarted the server')));
      expect(await get('/'), 'OK\n');

      acme.corruptCertificate = false;
      // A later check renews it and restarts with the new certificate.
      await waitFor(() => '${served.out}'.contains('restarted the server'));
      expect((await verify()).code, 0);

      shutdown.add(ProcessSignal.sigint);
      expect(await served.code, 0);
    });

    test('serves a static directory', () async {
      final site = Directory(pack_path.join(tmpDir.path, 'site'))..createSync();
      File(pack_path.join(site.path, 'index.html')).writeAsStringSync('home');
      await startServe(['--static', site.path, '--renew-interval', '1d']);
      expect(await get('/'), 'home');
    });

    test('serve keeps running when a renewal fails', () async {
      final served =
          await startServe(['--renew-days', '365', '--renew-interval', '1s']);
      acme.rejectFinalize = true;
      final started = DateTime.now();
      while (!'${served.err}'.contains('FAIL  renewing $_domain') &&
          DateTime.now().difference(started) < const Duration(seconds: 30)) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      expect('${served.err}', contains('FAIL  renewing $_domain'));
      expect(await get('/'), 'OK\n');
    });

    test('verify reports an expired certificate', () async {
      final expired = selfSignedCertificate(_domain, days: -1);
      final context = SecurityContext()
        ..useCertificateChainBytes(utf8.encode(expired.certificatePEM))
        ..usePrivateKeyBytes(utf8.encode(expired.privateKeyPEM));
      final server = await shelf_io.serve(
          (request) => Response.ok('expired'), '127.0.0.1', securePort,
          securityContext: context);
      try {
        final result = await verify();
        expect(result.code, 1);
        expect(result.out, contains('FAIL  $_domain: Certificate expired on'));
      } finally {
        await server.close(force: true);
      }
    });

    test('the challenge server answers challenges and self-checks', () async {
      final letsEncrypt = _TestLetsEncrypt(handler(), acme,
          port: port,
          securePort: securePort,
          bindingAddress: '127.0.0.1',
          production: false);
      final server = await RequestCommand(cli(StringBuffer(), StringBuffer()),
              renew: false)
          .serveChallenges(letsEncrypt);
      Future<(int, String)> fetch(String path) async {
        final client = HttpClient();
        try {
          final response = await (await client
                  .getUrl(Uri.parse('http://$_domain:$port$path')))
              .close();
          return (
            response.statusCode,
            await response.transform(utf8.decoder).join()
          );
        } finally {
          client.close(force: true);
        }
      }

      try {
        expect(await fetch('/.well-known/check/1'), (200, 'OK'));
        expect((await fetch('/.well-known/acme-challenge/x')).$1, 404);
        expect((await fetch('/other')).$1, 404);
      } finally {
        await server.close(force: true);
      }
    });

    test('renews while serving', () async {
      await startServe(['--renew-days', '365', '--renew-interval', '1s']);
      final started = DateTime.now();
      while (acme.certificatesIssued < 2 &&
          DateTime.now().difference(started) < const Duration(seconds: 30)) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      expect(acme.certificatesIssued, greaterThanOrEqualTo(2));
      // The restarted HTTPS server serves the renewed certificate.
      var matched = false;
      for (var i = 0; i < 50 && !matched; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
        matched = (await verify()).code == 0;
      }
      expect(matched, isTrue);
    });

    test('rejects invalid serve options', () async {
      final interval = await run(
          ['serve', _domain, ...acmeOptions(), '--renew-interval', 'often']);
      expect(interval.code, 64);
      final missing = await run(
          ['serve', _domain, ...acmeOptions(), '--static', '/no/such/dir']);
      expect(missing.code, 64);
    });
  });
}
