import 'dart:io';

import 'package:basic_utils/basic_utils.dart';
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
      var domain = 'foo.com';
      var email = 'contact@foo.com';

      var certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-1')));

      expect(await certificatesHandler.getAccountPEMKeyPair(), isNull);
      expect(await certificatesHandler.getDomainPEMKeyPair(domain), isNull);
      expect(await certificatesHandler.buildSecurityContext([domain]), isNull);

      var accountPEMKeyPair =
          await certificatesHandler.ensureAccountPEMKeyPair();

      expect(accountPEMKeyPair, isNotNull);
      expect(accountPEMKeyPair.publicKey, isNotNull);
      expect(accountPEMKeyPair.privateKey, isNotNull);

      var domainPEMKeyPair =
          await certificatesHandler.ensureDomainPEMKeyPair(domain);
      expect(domainPEMKeyPair, isNotNull);
      expect(domainPEMKeyPair.publicKey, isNotNull);
      expect(domainPEMKeyPair.privateKey, isNotNull);

      var csr = (await certificatesHandler.generateCSR(domain, email))!;
      expect(csr, isNotEmpty);

      // self sign:
      var csrSign = CryptoUtils.rsaSign(
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
      var certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-2')));

      var letsEncrypt = LetsEncrypt(certificatesHandler);

      expect(letsEncrypt.production, isFalse);

      expect(letsEncrypt.apiBaseURL,
          allOf(contains('letsencrypt.org'), contains('staging')));

      var checkCertificateStatus = await letsEncrypt.checkCertificate(
        'localhost',
        'contact@localhost',
        requestCertificate: false,
        forceRequestCertificate: false,
        retryInterval: Duration(milliseconds: 1),
      );

      expect(checkCertificateStatus, equals(CheckCertificateStatus.invalid));
    });

    test('ACME path + processACMEChallengeRequest', () async {
      var certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-3')));

      var letsEncrypt = LetsEncrypt(certificatesHandler);

      expect(
          LetsEncrypt.isACMEPath(
              '/.well-known/acme-challenge/Y73s3McbchxLs_NklRfW6HebjYrBmbVeKm0c9jbn3QI'),
          isTrue);

      expect(
          LetsEncrypt.isWellknownPath(
              '/.well-known/acme-challenge/Y73s3McbchxLs_NklRfW6HebjYrBmbVeKm0c9jbn3QI'),
          isTrue);

      expect(LetsEncrypt.isACMEPath('/.well-known/foo/123'), isFalse);

      expect(LetsEncrypt.isACMEPath('/well-known/'), isFalse);
      expect(LetsEncrypt.isWellknownPath('/well-known/'), isFalse);
      expect(LetsEncrypt.isACMEPath('/any/path'), isFalse);

      {
        var uri = Uri.parse(
            'http://foo.com/.well-known/acme-challenge/Y73s3McbchxLs_NklRfW6HebjYrBmbVeKm0c9jbn3QI');
        var request = Request('GET', uri, headers: {'host': 'foo.com'});

        // No challenge token expected:
        var response = letsEncrypt.processACMEChallengeRequest(request);
        expect(response.statusCode, equals(404));
      }

      {
        var uri = Uri.parse(
            'http://foo.com/.well-known/acme-challenge/Y73s3McbchxLs_NklRfW6HebjYrBmbVeKm0c9jbn3QI');
        var request = Request('GET', uri, headers: {'host': 'foo.com:8080'});

        // No challenge token expected:
        var response = letsEncrypt.processACMEChallengeRequest(request);
        expect(response.statusCode, equals(404));
      }
    });

    test('Self check path', () async {
      var certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-3')));

      var letsEncrypt = LetsEncrypt(certificatesHandler);

      expect(
          LetsEncrypt.isWellknownPath('/.well-known/check/123456789'), isTrue);

      expect(
          LetsEncrypt.isSelfCheckPath('/.well-known/check/123456789'), isTrue);

      expect(LetsEncrypt.isSelfCheckPath('/well-known/'), isFalse);
      expect(LetsEncrypt.isWellknownPath('/well-known/'), isFalse);
      expect(LetsEncrypt.isSelfCheckPath('/any/path'), isFalse);

      {
        var uri = Uri.parse('http://foo.com/.well-known/check/123456789');
        var request = Request('GET', uri, headers: {'host': 'foo.com'});

        var response = letsEncrypt.processSelfCheckRequest(request);
        expect(response.statusCode, equals(200));
      }
    });

    test('serve', () async {
      var certificatesHandler = CertificatesHandlerIO(
          Directory(pack_path.join(tmpDir.path, 'certs-4')));

      var letsEncrypt = LetsEncrypt(certificatesHandler);

      expect(letsEncrypt.production, isFalse);

      StateError? error;
      try {
        await letsEncrypt.startSecureServer(
          (request) => Response.ok('Requested: ${request.requestedUri}'),
          {'localhost': 'contact@localhost'},
          port: 9180,
          securePort: 9143,
          checkCertificate: true,
          requestCertificate: false,
          forceRequestCertificate: false,
        );
      } catch (e) {
        error = e as StateError;
      }

      expect(error, isNotNull);
      expect(
          error?.message,
          allOf(contains('No previous SecureContext'),
              contains("Can't request")));
    });

    tearDown(() {
      tmpDir.deleteSync(recursive: true);
    });
  });
}
