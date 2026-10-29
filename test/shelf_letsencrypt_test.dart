// ignore_for_file: avoid_catches_without_on_clauses

import 'dart:io';

import 'package:basic_utils/basic_utils.dart' hide Domain;
import 'package:path/path.dart' as pack_path;
import 'package:shelf/shelf.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';
import 'package:test/test.dart';

void main() {
  group('CertificatesHandlerIO', () {
    late Directory tmpDir;
    setUp(() {
      tmpDir = Directory.systemTemp.createTempSync('dart-test-1-tmp-');
      _chmod(tmpDir.path, '700');
      print('TMP DIR: $tmpDir');
    });

    test('basic', () async {
      const domain = Domain(name: 'foo.com', email: 'contact@foo.com');

      final certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-1')));

      expect(await certificatesHandler.getAccountPEMKeyPair(), isNull);
      expect(
          await certificatesHandler.getDomainPEMKeyPair(domain.name), isNull);
      expect(await certificatesHandler.buildSecurityContexts([domain]), isNull);

      final accountPEMKeyPair =
          await certificatesHandler.ensureAccountPEMKeyPair();

      expect(accountPEMKeyPair, isNotNull);
      expect(accountPEMKeyPair.publicKey, isNotNull);
      expect(accountPEMKeyPair.privateKey, isNotNull);

      final domainPEMKeyPair =
          await certificatesHandler.ensureDomainPEMKeyPair(domain.name);
      expect(domainPEMKeyPair, isNotNull);
      expect(domainPEMKeyPair.publicKey, isNotNull);
      expect(domainPEMKeyPair.privateKey, isNotNull);

      final csr =
          (await certificatesHandler.generateCSR(domain.name, domain.email))!;
      expect(csr, isNotEmpty);

      // self sign:
      final csrSign = CryptoUtils.rsaSign(
          domainPEMKeyPair.privateKey, CryptoUtils.getBytesFromPEMString(csr));

      expect(csrSign, isNotEmpty);
    });

    test('private keys and certificate directories are private', () async {
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'private-certs')));
      await handler.generateAccountPEMKeyPair();
      await handler.generateDomainPEMKeyPair('example.com');

      expect(handler.directory.statSync().mode & 0x3f, 0);
      expect(handler.fileAccountPrivateKeyPEM().statSync().mode & 0x3f, 0);
      expect(
          handler.fileDomainPrivateKeyPEM('example.com').statSync().mode & 0x3f,
          0);
      expect(
          handler
                  .fileDomainPrivateKeyPEM('example.com')
                  .parent
                  .statSync()
                  .mode &
              0x3f,
          0);
    }, skip: _posixSkip);

    test('existing permissive keys are secured without changing identity',
        () async {
      final root = Directory(pack_path.join(tmpDir.path, 'existing-certs'));
      final first = CertificatesHandlerIO(root);
      final account = await first.generateAccountPEMKeyPair();
      final domain = await first.generateDomainPEMKeyPair('example.com');
      final accountPem = account!.privateKeyPEM;
      final domainPem = domain!.privateKeyPEM;

      _chmod(first.fileAccountPrivateKeyPEM().path, '644');
      _chmod(first.fileDomainPrivateKeyPEM('example.com').path, '644');
      _chmod(first.fileAccountPrivateKeyPEM().parent.path, '755');
      _chmod(first.fileDomainPrivateKeyPEM('example.com').parent.path, '755');
      _chmod(root.path, '755');

      final migrated = CertificatesHandlerIO(root);
      expect(
          (await migrated.getAccountPEMKeyPair())!.privateKeyPEM, accountPem);
      expect((await migrated.getDomainPEMKeyPair('example.com'))!.privateKeyPEM,
          domainPem);
      expect(root.statSync().mode & 0x3f, 0);
      expect(migrated.fileAccountPrivateKeyPEM().statSync().mode & 0x3f, 0);
      expect(
          migrated.fileDomainPrivateKeyPEM('example.com').statSync().mode &
              0x3f,
          0);
    }, skip: _posixSkip);

    test('private-key links and incomplete pairs fail closed', () async {
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'linked-certs')));
      final pair = await handler.generateDomainPEMKeyPair('example.com');
      expect(pair, isNotNull);

      final publicKey = handler.fileDomainPublicKeyPEM('example.com');
      publicKey.deleteSync();
      await expectLater(
          handler.generateDomainPEMKeyPair('example.com'), throwsStateError);
      expect(
          handler.fileDomainPrivateKeyPEM('example.com').existsSync(), isTrue);

      final outside = File(pack_path.join(tmpDir.path, 'outside-private.pem'))
        ..writeAsStringSync('sentinel');
      final privateKey = handler.fileDomainPrivateKeyPEM('example.com');
      privateKey.deleteSync();
      Link(privateKey.path).createSync(outside.path);
      expect(() => handler.loadDomainPrivateKeyPEM('example.com'),
          throwsA(isA<FileSystemException>()));
      expect(outside.readAsStringSync(), 'sentinel');
    }, skip: _posixSkip);

    test('nested configured key and public paths still work', () async {
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'nested-certs')),
          privateKeyPEMFileName: 'private/privkey.pem',
          publicKeyPEMFileName: 'public/pubkey.pem');
      final pair = await handler.generateAccountPEMKeyPair();
      expect(pair, isNotNull);
      expect(handler.fileAccountPrivateKeyPEM().existsSync(), isTrue);
      expect(handler.fileAccountPublicKeyPEM().existsSync(), isTrue);
      expect(
          handler.fileAccountPrivateKeyPEM().parent.statSync().mode & 0x3f, 0);
    }, skip: _posixSkip);

    test('invalid public destination fails before private-key creation',
        () async {
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'invalid-public-certs')));
      final publicKey = handler.fileAccountPublicKeyPEM();
      publicKey.parent.createSync(recursive: true);
      Directory(publicKey.path).createSync();

      await expectLater(handler.generateAccountPEMKeyPair(),
          throwsA(isA<FileSystemException>()));
      expect(handler.fileAccountPrivateKeyPEM().existsSync(), isFalse);
    });

    test('storage checks and writes cannot resolve different roots', () {
      final safe = Directory(pack_path.join(tmpDir.path, 'safe'))..createSync();
      final elsewhere = Directory(pack_path.join(tmpDir.path, 'elsewhere'))
        ..createSync();
      final child = Directory(pack_path.join(elsewhere.path, 'child'))
        ..createSync();
      final actual = Directory(pack_path.join(elsewhere.path, 'store'))
        ..createSync();
      _chmod(actual.path, '755');
      Link(pack_path.join(safe.path, 'link')).createSync(child.path);

      expect(
          () => CertificatesHandlerIO(
              Directory(pack_path.join(safe.path, 'link', '..', 'store'))),
          throwsArgumentError);
      expect(actual.statSync().mode & 0x3f, isNot(0));
      expect(
          Directory(pack_path.join(safe.path, 'store')).existsSync(), isFalse);
      expect(
          () => CertificatesHandlerIO(
              Directory(pack_path.join(tmpDir.path, 'configured-paths')),
              privateKeyPEMFileName: 'link/../privkey.pem'),
          throwsArgumentError);
    }, skip: _posixSkip);

    test('symbolic links in the storage path are resolved', () {
      final real = Directory(pack_path.join(tmpDir.path, 'real'))..createSync();
      _chmod(real.path, '755');
      final alias = Link(pack_path.join(tmpDir.path, 'alias'))
        ..createSync(real.path);

      final handler =
          CertificatesHandlerIO(Directory(pack_path.join(alias.path, 'certs')));

      expect(
          handler.directory.path,
          equals(Directory(pack_path.join(real.path, 'certs'))
              .resolveSymbolicLinksSync()));
      expect(handler.fileAccountPrivateKeyPEM().path,
          startsWith(handler.directory.path));
    }, skip: _posixSkip);

    test('storage under a directory writable by others is rejected', () {
      final shared = Directory(pack_path.join(tmpDir.path, 'shared'))
        ..createSync();
      final certs = Directory(pack_path.join(shared.path, 'certs'));

      _chmod(shared.path, '777');
      expect(() => CertificatesHandlerIO(certs),
          throwsA(isA<FileSystemException>()));
      expect(certs.existsSync(), isFalse);

      // A sticky shared parent, like /tmp, is accepted:
      _chmod(shared.path, '1777');
      expect(CertificatesHandlerIO(certs).directory.existsSync(), isTrue);
    }, skip: _posixSkip);

    test('domain names cannot escape certificate storage', () async {
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'bounded-certs')));
      for (final invalid in ['../outside', r'..\outside', '/outside', 'a/b']) {
        expect(() => handler.fileDomainPrivateKeyPEM(invalid),
            throwsArgumentError);
        expect(
            () => handler.fileDomainPublicKeyPEM(invalid), throwsArgumentError);
        expect(
            () => handler.fileDomainFullChainPEM(invalid), throwsArgumentError);
        await expectLater(
            handler.generateDomainPEMKeyPair(invalid), throwsArgumentError);
        await expectLater(handler.saveSignedCertificateChain(invalid, ['test']),
            throwsArgumentError);
        expect(() => handler.isHandledDomainCertificate(invalid),
            throwsArgumentError);
        await expectLater(
            handler.buildSecurityContexts(
                [Domain(name: invalid, email: 'contact@example.com')],
                allowUnresolvedDomain: true),
            throwsArgumentError);
      }
      expect(Directory(pack_path.join(tmpDir.path, 'outside')).existsSync(),
          isFalse);
    });

    test('multi-label domains remain valid storage names', () async {
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'multi-label-certs')));
      for (final name in ['api.dev.example.com', 'www.example.co.uk']) {
        expect(Domain(name: name, email: '').isValidName, isTrue);
        final key = await handler.generateDomainPEMKeyPair(name);
        expect(key, isNotNull);
        expect(handler.fileDomainPrivateKeyPEM(name).existsSync(), isTrue);
      }
    });

    test('handled-domain discovery skips non-domain directories', () async {
      final certsDir =
          Directory(pack_path.join(tmpDir.path, 'discovery-certs'));
      final handler = CertificatesHandlerIO(certsDir);

      await _storeSelfSignedCertificate(handler, 'example.com');
      expect(handler.listAllHandledDomains(), equals(['example.com']));

      // Complete certificates stored under names that are not valid domains:
      final domainDir = Directory(pack_path.join(certsDir.path, 'example.com'));
      for (final name in [
        '.hidden.com',
        'not_a_domain',
        '-bad.example.com',
        'localhost',
      ]) {
        _copyDirectory(domainDir, pack_path.join(certsDir.path, name));
      }

      expect(handler.listAllHandledDomains(), equals(['example.com']));

      final securityContexts = await handler.buildSecurityContexts(
          [const Domain(name: 'example.com', email: 'contact@example.com')]);
      expect(securityContexts, isNotNull);
      expect(securityContexts, isNotEmpty);
    });

    test('handled-domain discovery supports nested PEM file names', () async {
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'nested-pem-certs')),
          privateKeyPEMFileName: pack_path.join('live', 'privkey.pem'),
          publicKeyPEMFileName: pack_path.join('live', 'pubkey.pem'),
          fullChainPEMFileName: pack_path.join('live', 'fullchain.pem'));

      await _storeSelfSignedCertificate(handler, 'example.com');

      expect(handler.listAllHandledDomains(), equals(['example.com']));
    });

    tearDown(() {
      tmpDir.deleteSync(recursive: true);
    });
  });

  group('LetsEncrypt', () {
    late Directory tmpDir;
    setUp(() {
      tmpDir = Directory.systemTemp.createTempSync('dart-test-1-tmp-');
      _chmod(tmpDir.path, '700');
      print('TMP DIR: $tmpDir');
    });

    test('basic', () async {
      final certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-2')));

      final letsEncrypt = LetsEncrypt(certificatesHandler);

      expect(letsEncrypt.production, isFalse);

      expect(letsEncrypt.apiBaseURL,
          allOf(contains('letsencrypt.org'), contains('staging')));

      final checkCertificateStatus = await letsEncrypt.checkCertificate(
        const Domain(name: 'localhost', email: 'contact@localhost'),
        retryInterval: const Duration(milliseconds: 1),
      );

      expect(checkCertificateStatus, equals(CheckCertificateStatus.invalid));
    });

    test('invalid request domain has no storage side effects', () async {
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'rejected-domain-certs')));
      final letsEncrypt = LetsEncrypt(handler);

      await expectLater(
          letsEncrypt.requestCertificate(
              const Domain(name: '../outside', email: 'contact@example.com')),
          throwsArgumentError);
      expect(handler.fileAccountPrivateKeyPEM().existsSync(), isFalse);
      expect(Directory(pack_path.join(tmpDir.path, 'outside')).existsSync(),
          isFalse);
    });

    test('ACME path + processACMEChallengeRequest', () async {
      final certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-3')));

      final letsEncrypt = LetsEncrypt(certificatesHandler);

      expect(
          LetsEncrypt.isACMEPath(
              '/.well-known/acme-challenge/Y73s3McbchxLs_NklRfW6HebjYrBmbVeKm0c9jbn3QI'),
          isTrue);

      expect(
          LetsEncrypt.isWellKnownPath(
              '/.well-known/acme-challenge/Y73s3McbchxLs_NklRfW6HebjYrBmbVeKm0c9jbn3QI'),
          isTrue);

      expect(LetsEncrypt.isACMEPath('/.well-known/foo/123'), isFalse);

      expect(LetsEncrypt.isACMEPath('/well-known/'), isFalse);
      expect(LetsEncrypt.isWellKnownPath('/well-known/'), isFalse);
      expect(LetsEncrypt.isACMEPath('/any/path'), isFalse);

      {
        final uri = Uri.parse(
            'http://foo.com/.well-known/acme-challenge/Y73s3McbchxLs_NklRfW6HebjYrBmbVeKm0c9jbn3QI');
        final request = Request('GET', uri, headers: {'host': 'foo.com'});

        // No challenge token expected:
        final response = letsEncrypt.processACMEChallengeRequest(request);
        expect(response.statusCode, equals(404));
      }

      {
        final uri = Uri.parse(
            'http://foo.com/.well-known/acme-challenge/Y73s3McbchxLs_NklRfW6HebjYrBmbVeKm0c9jbn3QI');
        final request = Request('GET', uri, headers: {'host': 'foo.com:8080'});

        // No challenge token expected:
        final response = letsEncrypt.processACMEChallengeRequest(request);
        expect(response.statusCode, equals(404));
      }
    });

    test('Self check path', () async {
      final certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-3')));

      final letsEncrypt = LetsEncrypt(certificatesHandler);

      expect(
          LetsEncrypt.isWellKnownPath('/.well-known/check/123456789'), isTrue);

      expect(
          LetsEncrypt.isSelfCheckPath('/.well-known/check/123456789'), isTrue);

      expect(LetsEncrypt.isSelfCheckPath('/well-known/'), isFalse);
      expect(LetsEncrypt.isWellKnownPath('/well-known/'), isFalse);
      expect(LetsEncrypt.isSelfCheckPath('/any/path'), isFalse);

      {
        final uri = Uri.parse('http://foo.com/.well-known/check/123456789');
        final request = Request('GET', uri, headers: {'host': 'foo.com'});

        final response = letsEncrypt.processSelfCheckRequest(request);
        expect(response.statusCode, equals(200));
      }
    });

    test('serve', () async {
      final certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-4')));

      final letsEncrypt = LetsEncrypt(
        certificatesHandler,
        port: 9180,
        securePort: 9143,
      );

      expect(letsEncrypt.production, isFalse);

      {
        ArgumentError? error;
        try {
          await letsEncrypt.startServer(
            (request) => Response.ok('Requested: ${request.requestedUri}'),
            [const Domain(name: 'localhost', email: 'contact@localhost')],
            requestCertificate: false,
          );
        } catch (e) {
          error = e as ArgumentError;
        }

        expect(error, isNotNull);
        expect(
            error?.message,
            allOf(contains("Empty `domains`"),
                contains("No valid domain provided")));
      }

      {
        StateError? error;
        try {
          await letsEncrypt.startServer(
            (request) => Response.ok('Requested: ${request.requestedUri}'),
            [const Domain(name: 'example.com', email: 'contact@example.com')],
            requestCertificate: false,
          );
        } catch (e) {
          error = e as StateError;
        }

        expect(error, isNotNull);
        expect(
            error?.message,
            allOf(contains("Can't load all `SecurityContext`s"),
                contains("can't request")));
      }
    });

    tearDown(() {
      tmpDir.deleteSync(recursive: true);
    });
  });

  group('Domain', () {
    test('isValidName', () {
      final label63 = 'a' * 63;

      for (final name in [
        'example.com',
        'EXAMPLE.COM',
        'a-b.example.com',
        'api.dev.example.com',
        'www.example.co.uk',
        'xn--bcher-kva.example',
        '123.example.com',
        'example.xn--p1ai',
        '$label63.com',
      ]) {
        expect(Domain(name: name, email: '').isValidName, isTrue, reason: name);
      }

      for (final name in [
        '',
        'localhost',
        'example.com.',
        '.example.com',
        'a..com',
        '-a.com',
        'a-.com',
        '*.example.com',
        'exa mple.com',
        'example.com\n',
        'a_b.example.com',
        '1.2.3.4',
        '127.0.0.1',
        'example.123',
        '../outside',
        'a/b.com',
        r'a\b.com',
        'c:.com',
        '${'a' * 64}.com',
        // 255 chars, over the 253 limit:
        List.filled(4, label63).join('.'),
      ]) {
        expect(Domain(name: name, email: '').isValidName, isFalse,
            reason: name);
      }
    });
  });
}

Future<void> _storeSelfSignedCertificate(
    CertificatesHandlerIO handler, String cn) async {
  final keyPair = await handler.ensureDomainPEMKeyPair(cn);
  final csr = (await handler.generateCSR(cn, 'contact@$cn'))!;
  final certificate =
      X509Utils.generateSelfSignedCertificate(keyPair.privateKey, csr, 30);
  await handler.saveSignedCertificateChain(cn, [certificate]);
}

/// Owner-only POSIX permissions are not enforced on Windows.
final _posixSkip = Platform.isWindows ? 'POSIX permissions' : null;

void _chmod(String path, String mode) {
  if (Platform.isWindows) return;
  final result = Process.runSync('chmod', [mode, path]);
  if (result.exitCode != 0) {
    throw FileSystemException('chmod $mode failed: ${result.stderr}', path);
  }
}

void _copyDirectory(Directory from, String toPath) {
  for (final file in from.listSync(recursive: true).whereType<File>()) {
    final target = File(
        pack_path.join(toPath, pack_path.relative(file.path, from: from.path)));
    target.parent.createSync(recursive: true);
    file.copySync(target.path);
  }
}
