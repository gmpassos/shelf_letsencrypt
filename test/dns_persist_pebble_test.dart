// Integration-style test setup keeps long environment names and URLs intact.
// ignore_for_file: lines_longer_than_80_chars

import 'dart:convert';
import 'dart:io';

import 'package:acme_client/acme_client.dart' show AcmeConnection;
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:path/path.dart' as pack_path;
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';
import 'package:test/test.dart';

const _pebbleEnabledEnv = 'ACME_PEBBLE_ENABLE_TESTS';
const _pebbleBaseUrlEnv = 'ACME_PEBBLE_BASE_URL';
const _pebbleManagementUrlEnv = 'ACME_PEBBLE_MANAGEMENT_URL';
const _pebbleIdentifierEnv = 'ACME_PEBBLE_IDENTIFIER';
const _pebbleTrustedRootEnv = 'ACME_PEBBLE_TRUSTED_ROOT';

void main() {
  final enabled = Platform.environment[_pebbleEnabledEnv] == 'true';
  final baseUrl =
      Platform.environment[_pebbleBaseUrlEnv] ?? 'https://localhost:14000/dir';
  final managementUrl =
      Platform.environment[_pebbleManagementUrlEnv] ?? 'http://localhost:8055';
  final trustedRootPath = Platform.environment[_pebbleTrustedRootEnv];

  late Directory tmpDir;

  setUp(() {
    tmpDir = Directory.systemTemp.createTempSync(
      'shelf-letsencrypt-pebble-',
    );
  });

  tearDown(() {
    if (tmpDir.existsSync()) {
      tmpDir.deleteSync(recursive: true);
    }
  });

  test(
    'automated dns-persist-01 issuance',
    () async {
      final identifier = _identifier('automated', Platform.environment);
      final certificatesHandler = _certificatesHandler(tmpDir);
      final letsEncrypt = _letsEncrypt(
        certificatesHandler,
        baseUrl: baseUrl,
        managementUrl: managementUrl,
        trustedRootPath: trustedRootPath,
        expectedIdentifier: identifier,
      );

      final ok = await letsEncrypt.requestCertificate(
        Domain(name: identifier, email: 'contact@$identifier'),
      );

      expect(ok, isTrue);
      _expectStoredCertificate(certificatesHandler, identifier);
    },
    skip: enabled
        ? false
        : 'Set $_pebbleEnabledEnv=true to run against the local Pebble harness.',
  );

  test(
    'manual dns-persist-01 prepare and complete',
    () async {
      final identifier = _identifier('manual', Platform.environment);
      final certificatesHandler = _certificatesHandler(tmpDir);
      final letsEncrypt = _letsEncrypt(
        certificatesHandler,
        baseUrl: baseUrl,
        managementUrl: managementUrl,
        trustedRootPath: trustedRootPath,
      );
      final pending = await letsEncrypt.prepareDnsPersistCertificateRequest(
        Domain(name: identifier, email: 'contact@$identifier'),
      );

      expect(pending.domainName, identifier);
      await _publishTxtRecord(
        managementUrl,
        pending.proof.txtRecordName,
        pending.proof.txtRecordValue,
      );

      expect(await pending.complete(), isTrue);
      expect(await pending.complete(), isTrue);
      _expectStoredCertificate(certificatesHandler, identifier);
    },
    skip: enabled
        ? false
        : 'Set $_pebbleEnabledEnv=true to run against the local Pebble harness.',
  );

  test(
    'manual dns-persist-01 forced certificate request',
    () async {
      final identifier = _identifier('manual-force', Platform.environment);
      final certificatesHandler = _certificatesHandler(tmpDir);
      final letsEncrypt = _letsEncrypt(
        certificatesHandler,
        baseUrl: baseUrl,
        managementUrl: managementUrl,
        trustedRootPath: trustedRootPath,
      );

      final first = await letsEncrypt.prepareDnsPersistCertificateRequest(
        Domain(name: identifier, email: 'contact@$identifier'),
      );
      await _publishTxtRecord(
        managementUrl,
        first.proof.txtRecordName,
        first.proof.txtRecordValue,
      );
      expect(await first.complete(), isTrue);

      final second = await letsEncrypt.prepareDnsPersistCertificateRequest(
        Domain(name: identifier, email: 'contact@$identifier'),
      );
      await _publishTxtRecord(
        managementUrl,
        second.proof.txtRecordName,
        second.proof.txtRecordValue,
      );
      expect(
        await second.complete(forceRequestCertificate: true),
        isTrue,
      );
      _expectStoredCertificate(certificatesHandler, identifier);
    },
    skip: enabled
        ? false
        : 'Set $_pebbleEnabledEnv=true to run against the local Pebble harness.',
  );

  test(
    'checkCertificate force renews through dns-persist-01',
    () async {
      final identifier = _identifier('renewal', Platform.environment);
      final certificatesHandler = _certificatesHandler(tmpDir);
      final letsEncrypt = _letsEncrypt(
        certificatesHandler,
        baseUrl: baseUrl,
        managementUrl: managementUrl,
        trustedRootPath: trustedRootPath,
        expectedIdentifier: identifier,
      );
      final domain = Domain(name: identifier, email: 'contact@$identifier');

      expect(await letsEncrypt.requestCertificate(domain), isTrue);
      final status = await letsEncrypt.checkCertificate(
        domain,
        requestCertificate: true,
        forceRequestCertificate: true,
        maxRetries: 1,
      );

      expect(status, CheckCertificateStatus.okRefreshed);
      _expectStoredCertificate(certificatesHandler, identifier);
    },
    skip: enabled
        ? false
        : 'Set $_pebbleEnabledEnv=true to run against the local Pebble harness.',
  );

  test(
    'dns-persist-01 fails when TXT record is missing',
    () async {
      final identifier = _identifier('missing-txt', Platform.environment);
      final certificatesHandler = _certificatesHandler(tmpDir);
      final letsEncrypt = _letsEncrypt(
        certificatesHandler,
        baseUrl: baseUrl,
        managementUrl: managementUrl,
        trustedRootPath: trustedRootPath,
        expectedIdentifier: identifier,
        publishRecord: false,
      );

      await expectLater(
        () => letsEncrypt.requestCertificate(
          Domain(name: identifier, email: 'contact@$identifier'),
        ),
        throwsA(anything),
      );
      expect(
        certificatesHandler.fileDomainFullChainPEM(identifier).existsSync(),
        isFalse,
      );
    },
    skip: enabled
        ? false
        : 'Set $_pebbleEnabledEnv=true to run against the local Pebble harness.',
  );
}

CertificatesHandlerIO _certificatesHandler(Directory tmpDir) =>
    CertificatesHandlerIO(
      Directory(pack_path.join(tmpDir.path, 'certs')),
    );

LetsEncrypt _letsEncrypt(
  CertificatesHandler certificatesHandler, {
  required String baseUrl,
  required String managementUrl,
  required String? trustedRootPath,
  String? expectedIdentifier,
  bool publishRecord = true,
}) =>
    LetsEncrypt(
      certificatesHandler,
      selfTest: false,
      challengeType: LetsEncryptChallengeType.dnsPersist,
      acmeDirectoryUrl: baseUrl,
      acmeConnection: AcmeConnection(
        baseUrl: baseUrl,
        dio: _buildPebbleDio(trustedRootPath),
      ),
      dnsPersistChallengePublisher: (domainName, proof) async {
        if (expectedIdentifier != null) {
          expect(domainName, expectedIdentifier);
        }
        if (!publishRecord) {
          return;
        }
        await _publishTxtRecord(
          managementUrl,
          proof.txtRecordName,
          proof.txtRecordValue,
        );
      },
    );

void _expectStoredCertificate(
  CertificatesHandlerIO certificatesHandler,
  String identifier,
) {
  final fullChainFile = certificatesHandler.fileDomainFullChainPEM(
    identifier,
  );
  expect(fullChainFile.existsSync(), isTrue);
  expect(fullChainFile.readAsStringSync(), contains('BEGIN CERTIFICATE'));
}

String _identifier(String prefix, Map<String, String> environment) =>
    environment[_pebbleIdentifierEnv] ?? '$prefix.example.com';

Future<void> _publishTxtRecord(
  String managementUrl,
  String host,
  String value,
) async {
  final managementClient = Dio();
  await managementClient.post<void>(
    '$managementUrl/set-txt',
    data: json.encode({'host': _normalizeTxtHost(host), 'value': value}),
    options: Options(headers: {'Content-Type': 'application/json'}),
  );
}

String _normalizeTxtHost(String host) => host.endsWith('.') ? host : '$host.';

Dio _buildPebbleDio(String? trustedRootPath) => Dio()
  ..httpClientAdapter = IOHttpClientAdapter(
    createHttpClient: () {
      final context = SecurityContext();
      if (trustedRootPath != null && trustedRootPath.isNotEmpty) {
        context.setTrustedCertificates(trustedRootPath);
      }
      final client = HttpClient(context: context);
      if (trustedRootPath == null || trustedRootPath.isEmpty) {
        client.badCertificateCallback = (certificate, host, port) => true;
      }
      return client;
    },
  );
