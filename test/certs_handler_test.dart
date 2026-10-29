import 'dart:io';

import 'package:path/path.dart' as pack_path;
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';
import 'package:test/test.dart';

import 'support/certificates.dart';

/// Owner-only POSIX permissions are not enforced on Windows.
final _posixSkip = Platform.isWindows ? 'POSIX permissions' : null;

void main() {
  late Directory tmpDir;

  setUp(() {
    tmpDir = Directory.systemTemp.createTempSync('shelf-letsencrypt-handler-');
    if (!Platform.isWindows) {
      Process.runSync('chmod', ['700', tmpDir.path]);
    }
  });

  tearDown(() => tmpDir.deleteSync(recursive: true));

  CertificatesHandlerIO handlerAt(String name,
          {String? privateKeyPEMFileName}) =>
      CertificatesHandlerIO(Directory(pack_path.join(tmpDir.path, name)),
          privateKeyPEMFileName: privateKeyPEMFileName ??
              CertificatesHandler.defaultPrivateKeyPEMFileName);

  group('PEM helpers', () {
    final first = selfSignedCertificate('a.example.com').certificatePEM;
    final second = selfSignedCertificate('b.example.com').certificatePEM;

    test('splitPEMs and joinPEMs', () {
      final joined = CertificatesHandler.joinPEMs([first, second]);
      expect(joined, endsWith('-----END CERTIFICATE-----\n'));
      expect(joined, isNot(contains('\n\n\n')));

      final split = CertificatesHandler.splitPEMs(joined);
      expect(split, hasLength(2));
      expect(split[0], equals(CertificatesHandler.fixPEM(first)));
      expect(split[1], equals(CertificatesHandler.fixPEM(second)));
    });

    test('fixPEM puts the markers on their own lines', () {
      final body = first
          .replaceAll('-----BEGIN CERTIFICATE-----\n', '')
          .replaceAll('\n-----END CERTIFICATE-----', '')
          .trim();
      final oneLine = '  -----BEGIN CERTIFICATE-----$body'
          '-----END CERTIFICATE-----  ';

      expect(
          CertificatesHandler.fixPEM(oneLine),
          equals('-----BEGIN CERTIFICATE-----\n$body\n'
              '-----END CERTIFICATE-----\n'));
    });

    test('isCertificateExpired', () {
      final handler = handlerAt('expiry');
      expect(handler.isCertificateExpired(first), isFalse);
      expect(
          handler.isCertificateExpired(
              selfSignedCertificate('old.example.com', days: -1)
                  .certificatePEM),
          isTrue);
      expect(handler.isCertificateExpired('not a certificate'), isTrue);
    });
  });

  group('DomainCertificate', () {
    final a = selfSignedCertificate('a.example.com');
    final b = selfSignedCertificate('b.example.com');

    test('DomainCertificatePEM', () {
      final certificate = DomainCertificatePEM(
          ['b.example.com', 'a.example.com', 'a.example.com'],
          a.certificatePEM,
          a.privateKeyPEM);

      expect(certificate.domains, equals(['a.example.com', 'b.example.com']));
      expect(
          certificate,
          equals(DomainCertificatePEM(['a.example.com', 'b.example.com'],
              b.certificatePEM, b.privateKeyPEM)));
      expect(
          certificate.hashCode,
          equals(
              DomainCertificatePEM(['a.example.com', 'b.example.com'], '', '')
                  .hashCode));
      expect('$certificate', contains('a.example.com'));

      certificate.define(SecurityContext());
    });

    test('merge', () {
      final merged = DomainCertificatePEM(
              ['a.example.com'], a.certificatePEM, a.privateKeyPEM)
          .merge(DomainCertificatePEM(
              ['b.example.com'], b.certificatePEM, b.privateKeyPEM));

      expect(merged.domains, equals(['a.example.com', 'b.example.com']));
      expect(merged.fullChainPEM, contains(a.certificatePEM));
      expect(merged.fullChainPEM, contains(b.certificatePEM));
      expect(merged.privateKeyPEM, contains(b.privateKeyPEM));
    });

    test('DomainCertificateFilePath reads its files', () {
      final chain = File(pack_path.join(tmpDir.path, 'fullchain.pem'))
        ..writeAsStringSync(a.certificatePEM);
      final key = File(pack_path.join(tmpDir.path, 'privkey.pem'))
        ..writeAsStringSync(a.privateKeyPEM);

      final certificate =
          DomainCertificateFilePath(['a.example.com'], chain.path, key.path);
      expect(certificate.fullChainPEM, equals(a.certificatePEM));
      expect(certificate.privateKeyPEM, equals(a.privateKeyPEM));
    });

    test('SecurityContextBuilder maps every domain', () {
      final builder = SecurityContextBuilder([
        DomainCertificatePEM(['a.example.com', 'www.a.example.com'],
            a.certificatePEM, a.privateKeyPEM),
        DomainCertificatePEM(
            ['b.example.com'], b.certificatePEM, b.privateKeyPEM),
      ]);

      final contexts = builder.buildAll();
      expect(
          contexts.keys,
          unorderedEquals(
              ['a.example.com', 'www.a.example.com', 'b.example.com']));
      expect(contexts['a.example.com'], same(contexts['www.a.example.com']));
    });
  });

  group('CertificatesHandlerIO', () {
    test('buildSecurityContexts loads all handled domains', () async {
      final handler = handlerAt('all-domains');
      await storeSelfSignedCertificate(handler, 'a.example.com');
      await storeSelfSignedCertificate(handler, 'b.example.com');
      const a = Domain(name: 'a.example.com', email: 'admin@example.com');

      expect((await handler.buildSecurityContexts([a]))!.keys,
          unorderedEquals(['a.example.com', 'b.example.com']));
      expect(
          (await handler
                  .buildSecurityContexts([a], loadAllHandledDomains: false))!
              .keys,
          equals(['a.example.com']));
      expect(handler.listHandledDomains(['a.example.com', 'c.example.com']),
          equals(['a.example.com']));
    });

    test('buildSecurityContexts with unresolved domains', () async {
      final handler = handlerAt('unresolved');
      await storeSelfSignedCertificate(handler, 'a.example.com');
      const domains = [
        Domain(name: 'a.example.com', email: 'admin@example.com'),
        Domain(name: 'missing.example.com', email: 'admin@example.com'),
      ];

      expect(await handler.buildSecurityContexts(domains), isNull);
      expect(
          (await handler.buildSecurityContexts(domains,
                  allowUnresolvedDomain: true))!
              .keys,
          equals(['a.example.com']));
      expect(handler.listNotHandledDomains(domains).map((d) => d.name),
          equals(['missing.example.com']));
    });

    test('expired and unloadable certificates are not handled', () async {
      final handler = handlerAt('unusable');
      await storeSelfSignedCertificate(handler, 'old.example.com', days: -1);
      expect(handler.isHandledDomainCertificate('old.example.com'), isFalse);

      await storeSelfSignedCertificate(handler, 'bad.example.com');
      // A different key than the certificate's:
      await handler.generateDomainPEMKeyPair('bad.example.com', force: true);
      expect(
          handler.isHandledDomainCertificate('bad.example.com',
              checkSecurityContext: false),
          isTrue);
      expect(handler.isHandledDomainCertificate('bad.example.com'), isFalse);
    });

    test('generateDomainPEMKeyPair returns the stored pair', () async {
      final handler = handlerAt('existing-pair');
      final pair = await handler.generateDomainPEMKeyPair('a.example.com');
      final again = await handler.generateDomainPEMKeyPair('a.example.com');
      expect(again!.privateKeyPEM, equals(pair!.privateKeyPEM));

      final other = await handler.generateDomainPEMKeyPair('b.example.com');
      handler
          .fileDomainPublicKeyPEM('a.example.com')
          .writeAsStringSync(other!.publicKeyPEM);
      await expectLater(
          handler.generateDomainPEMKeyPair('a.example.com'),
          throwsA(isA<StateError>()
              .having((e) => e.message, 'message', contains('do not match'))));
    });

    test('generateCSR with subject attributes', () async {
      final handler = handlerAt('csr');
      expect(await handler.generateCSR('a.example.com', 'admin@example.com'),
          isNull);

      await handler.ensureDomainPEMKeyPair('a.example.com');
      final csr = await handler.generateCSR(
          'a.example.com', 'admin@example.com',
          organizationName: 'Org',
          organizationUnit: 'Unit',
          locality: 'City',
          state: 'State',
          country: 'BR');
      expect(csr, contains('CERTIFICATE REQUEST'));
    });

    test('saveSignedCertificateChain requires a regular file', () async {
      final handler = handlerAt('chain-destination');
      Directory(handler.fileDomainFullChainPEM('a.example.com').path)
          .createSync(recursive: true);

      await expectLater(
          handler.saveSignedCertificateChain('a.example.com', ['chain']),
          throwsA(isA<FileSystemException>()));
    });

    test('certificate chain recreates a removed storage root', () async {
      final handler = handlerAt('removed-chain-root');
      handler.directory.deleteSync(recursive: true);

      await handler.saveSignedCertificateChain('a.example.com', ['chain']);
      expect(
          handler.fileDomainFullChainPEM('a.example.com').existsSync(), isTrue);
    });

    test('certificate chain rejects a linked domain directory', () async {
      final handler = handlerAt('linked-chain-parent');
      final outside = Directory(pack_path.join(tmpDir.path, 'outside-chain'))
        ..createSync();
      final victim = File(pack_path.join(outside.path, 'fullchain.pem'))
        ..writeAsStringSync('sentinel');
      Link(pack_path.join(handler.directory.path, 'a.example.com'))
          .createSync(outside.path);

      await expectLater(
          handler.saveSignedCertificateChain('a.example.com', ['replacement']),
          throwsA(isA<FileSystemException>()));
      expect(victim.readAsStringSync(), 'sentinel');
    }, skip: _posixSkip);

    test('certificate chain rejects a linked nested parent', () async {
      final root =
          Directory(pack_path.join(tmpDir.path, 'linked-chain-nested'));
      final handler = CertificatesHandlerIO(root,
          fullChainPEMFileName: 'nested/fullchain.pem');
      final domain = Directory(pack_path.join(root.path, 'a.example.com'))
        ..createSync();
      final outside = Directory(pack_path.join(tmpDir.path, 'outside-nested'))
        ..createSync();
      final victim = File(pack_path.join(outside.path, 'fullchain.pem'))
        ..writeAsStringSync('sentinel');
      Link(pack_path.join(domain.path, 'nested')).createSync(outside.path);

      await expectLater(
          handler.saveSignedCertificateChain('a.example.com', ['replacement']),
          throwsA(isA<FileSystemException>()));
      expect(victim.readAsStringSync(), 'sentinel');
    }, skip: _posixSkip);

    test('public key rejects a linked nested parent', () async {
      final root =
          Directory(pack_path.join(tmpDir.path, 'linked-public-parent'));
      final handler = CertificatesHandlerIO(root,
          publicKeyPEMFileName: 'nested/pubkey.pem');
      final domain = Directory(pack_path.join(root.path, 'a.example.com'))
        ..createSync();
      final outside = Directory(pack_path.join(tmpDir.path, 'outside-public'))
        ..createSync();
      final victim = File(pack_path.join(outside.path, 'pubkey.pem'))
        ..writeAsStringSync('sentinel');
      Link(pack_path.join(domain.path, 'nested')).createSync(outside.path);

      await expectLater(
          handler.generateDomainPEMKeyPair('a.example.com', force: true),
          throwsA(isA<FileSystemException>()));
      expect(victim.readAsStringSync(), 'sentinel');
    }, skip: _posixSkip);

    test('external public and chain paths retain their permissions', () async {
      final publicDir = Directory(pack_path.join(tmpDir.path, 'public'))
        ..createSync();
      Process.runSync('chmod', ['755', publicDir.path]);
      final publicFile = File(pack_path.join(publicDir.path, 'pubkey.pem'));
      final chainFile =
          File(pack_path.join(tmpDir.path, 'new-chain', 'chain.pem'));
      final handler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'external-public')),
          publicKeyPEMFileName: publicFile.path,
          fullChainPEMFileName: chainFile.path);

      await handler.generateDomainPEMKeyPair('a.example.com');
      await handler.saveSignedCertificateChain('a.example.com', ['chain']);
      expect(publicFile.existsSync(), isTrue);
      expect(chainFile.existsSync(), isTrue);
      expect(publicDir.statSync().mode & 0x1ff, 0x1ed);
    }, skip: _posixSkip);

    test('toString', () {
      final handler = handlerAt('to-string');
      expect('$handler', contains(handler.directory.path));
    });
  });

  group('private-key storage', () {
    test('re-creates a removed storage directory', () async {
      final handler = handlerAt('removed');
      handler.directory.deleteSync(recursive: true);

      await handler.generateAccountPEMKeyPair();
      expect(handler.fileAccountPrivateKeyPEM().existsSync(), isTrue);
      expect(handler.directory.statSync().mode & 0x3f, 0);
    }, skip: _posixSkip);

    test('rejects storage under a file', () {
      final file = File(pack_path.join(tmpDir.path, 'file'))
        ..writeAsStringSync('');
      expect(
          () => CertificatesHandlerIO(
              Directory(pack_path.join(file.path, 'certs'))),
          throwsA(isA<FileSystemException>()));
      expect(() => CertificatesHandlerIO(Directory(file.path)),
          throwsA(isA<FileSystemException>()));
    }, skip: _posixSkip);

    test('rejects a private key with extra hard links', () async {
      final handler = handlerAt('hard-link');
      await handler.generateDomainPEMKeyPair('a.example.com');
      hardLink(handler.fileDomainPrivateKeyPEM('a.example.com').path,
          pack_path.join(tmpDir.path, 'copy.pem'));

      expect(
          () => handler.loadDomainPrivateKeyPEM('a.example.com'),
          throwsA(isA<FileSystemException>()
              .having((e) => e.message, 'message', contains('link count'))));
    }, skip: _posixSkip);

    test('external private-key directory must be owner-only', () async {
      final external = Directory(pack_path.join(tmpDir.path, 'keys'))
        ..createSync();
      final keyPath = pack_path.join(external.path, 'privkey.pem');

      Process.runSync('chmod', ['755', external.path]);
      final handler = handlerAt('external', privateKeyPEMFileName: keyPath);
      await expectLater(
          handler.generateAccountPEMKeyPair(),
          throwsA(isA<FileSystemException>().having(
              (e) => e.message, 'message', contains('must be owner-only'))));

      Process.runSync('chmod', ['700', external.path]);
      await handler.generateAccountPEMKeyPair();
      expect(File(keyPath).statSync().mode & 0x3f, 0);
    }, skip: _posixSkip);

    test('external private-key directory must exist', () async {
      final handler = handlerAt('external-missing',
          privateKeyPEMFileName:
              pack_path.join(tmpDir.path, 'missing', 'privkey.pem'));
      await expectLater(handler.generateAccountPEMKeyPair(),
          throwsA(isA<FileSystemException>()));
    }, skip: _posixSkip);
  });
}
