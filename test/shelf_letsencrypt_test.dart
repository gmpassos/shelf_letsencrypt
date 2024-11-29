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

    tearDown(() {
      tmpDir.deleteSync(recursive: true);
    });
  });

  group('LetsEncrypt', () {
    late Directory tmpDir;
    setUp(() {
      tmpDir = Directory.systemTemp.createTempSync('dart-test-1-tmp-');
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

      StateError? error;
      try {
        await letsEncrypt.startServer(
          (request) => Response.ok('Requested: ${request.requestedUri}'),
          [const Domain(name: 'localhost', email: 'contact@localhost')],
          requestCertificate: false,
        );
      } catch (e) {
        error = e as StateError;
      }

      expect(error, isNotNull);
      expect(
          error?.message,
          allOf(contains('No previous SecureContext'),
              contains("can't request")));
    });

    tearDown(() {
      tmpDir.deleteSync(recursive: true);
    });
  });
}
