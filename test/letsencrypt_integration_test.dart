import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as pack_path;
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';
import 'package:test/test.dart';

import 'support/certificates.dart';
import 'support/fake_acme_server.dart';
import 'support/loopback_http_overrides.dart';

/// [LetsEncrypt] against a [FakeAcmeServer], with servers on loopback.
class _TestLetsEncrypt extends LetsEncrypt {
  _TestLetsEncrypt(super.certificatesHandler, this.acme,
      {required super.port, required super.securePort, super.log})
      : super(bindingAddress: '127.0.0.1');

  final FakeAcmeServer acme;

  @override
  String get apiBaseURL => acme.baseUrl;
}

const _domain = Domain(name: 'www.example.com', email: 'admin@example.com');
const _domain2 = Domain(name: 'api.example.com', email: 'admin@example.com');

void main() {
  late Directory tmpDir;
  late FakeAcmeServer acme;
  late _TestLetsEncrypt letsEncrypt;
  late List<String> logs;
  final servers = <HttpServer>[];

  setUpAll(() => HttpOverrides.global = LoopbackHttpOverrides());
  tearDownAll(() => HttpOverrides.global = null);

  setUp(() async {
    tmpDir = Directory.systemTemp.createTempSync('shelf-letsencrypt-it-');
    if (!Platform.isWindows) {
      Process.runSync('chmod', ['700', tmpDir.path]);
    }
    final port = await freePort();
    var securePort = await freePort();
    while (securePort == port) {
      securePort = await freePort();
    }
    acme = FakeAcmeServer(challengePort: port);
    await acme.start();
    logs = [];
    letsEncrypt = _TestLetsEncrypt(
        CertificatesHandlerIO(Directory(pack_path.join(tmpDir.path, 'certs'))),
        acme,
        port: port,
        securePort: securePort,
        log: (level, message, error, stackTrace) =>
            logs.add('[$level] $message ${error ?? ''}'));
  });

  tearDown(() async {
    for (final server in servers) {
      await server.close(force: true);
    }
    servers.clear();
    await acme.close();
    tmpDir.deleteSync(recursive: true);
  });

  Future<({HttpServer http, HttpServer https})> startServer(
      List<Domain> domains,
      {bool forceRequestCertificate = false,
      bool requestCertificate = true}) async {
    final started = await letsEncrypt.startServer(
        (request) => Response.ok('Hello ${request.requestedUri.host}'), domains,
        forceRequestCertificate: forceRequestCertificate,
        requestCertificate: requestCertificate);
    servers.addAll([started.http, started.https]);
    return started;
  }

  Future<void> closeServers() async {
    for (final server in servers) {
      await server.close(force: true);
    }
    servers.clear();
  }

  Future<(String body, X509Certificate? certificate)> get(Uri url) async {
    final client = HttpClient();
    try {
      final response = await (await client.getUrl(url)).close();
      return (
        await response.transform(utf8.decoder).join(),
        response.certificate
      );
    } finally {
      client.close(force: true);
    }
  }

  /// Serves only the ACME challenges of [letsEncrypt], on its HTTP port.
  Future<HttpServer> serveChallenges() => serve(
      letsEncrypt.processACMEChallengeRequest, '127.0.0.1', letsEncrypt.port);

  Uri https(Domain domain, [String path = '/']) =>
      Uri.parse('https://${domain.name}:${letsEncrypt.securePort}$path');

  group('startServer', () {
    test('requests, stores and serves a certificate', () async {
      await startServer([_domain]);

      expect(acme.certificatesIssued, equals(1));
      expect(letsEncrypt.certificatesHandler.listAllHandledDomains(),
          equals([_domain.name]));
      expect(letsEncrypt.getChallengeToken(_domain.name), isNull);

      final (body, certificate) = await get(https(_domain));
      expect(body, equals('Hello ${_domain.name}'));
      expect(certificate?.subject, contains(_domain.name));
      expect(certificate?.issuer, contains('Fake ACME CA'));

      final (httpBody, _) = await get(
          Uri.parse('http://${_domain.name}:${letsEncrypt.port}/page'));
      expect(httpBody, equals('Hello ${_domain.name}'));

      final (check, _) = await get(https(_domain, '/.well-known/check/1'));
      expect(check, equals('OK'));
    });

    test('reuses a valid certificate', () async {
      await startServer([_domain]);
      await closeServers();

      await startServer([_domain]);
      expect(acme.certificatesIssued, equals(1));
      expect(
          logs,
          contains(
              endsWith('CheckCertificateStatus: CheckCertificateStatus.ok ')));
    });

    test('renews with forceRequestCertificate and restarts HTTPS', () async {
      await startServer([_domain]);
      final (_, first) = await get(https(_domain));
      await closeServers();

      final started =
          await startServer([_domain], forceRequestCertificate: true);
      expect(acme.certificatesIssued, equals(2));

      final (_, renewed) = await get(https(_domain));
      expect(renewed?.pem, isNot(equals(first?.pem)));
      expect(started.https.port, equals(letsEncrypt.securePort));
    });

    test('serves multiple domains with SNI', () async {
      await startServer([_domain, _domain2]);
      expect(acme.certificatesIssued, equals(2));

      for (final domain in [_domain, _domain2]) {
        final (body, certificate) = await get(https(domain));
        expect(body, equals('Hello ${domain.name}'));
        expect(certificate?.subject, contains(domain.name));
      }
    });

    test('ignores invalid domains in an unmodifiable list', () async {
      const domains = [
        _domain,
        Domain(name: 'localhost', email: 'admin@example.com')
      ];
      await startServer(domains);
      expect(acme.certificatesIssued, equals(1));
      expect(domains, hasLength(2));
    });

    test('releases its ports when startup fails', () async {
      await expectLater(
          startServer([_domain], requestCertificate: false), throwsStateError);

      final http = await ServerSocket.bind(
          InternetAddress.loopbackIPv4, letsEncrypt.port);
      await http.close();
    });

    test('fails and releases its ports when the request fails', () async {
      acme.rejectNewOrder = true;
      await expectLater(startServer([_domain]), throwsStateError);

      final http = await ServerSocket.bind(
          InternetAddress.loopbackIPv4, letsEncrypt.port);
      await http.close();
    });

    test('fails when a certificate check fails', () async {
      await startServer([_domain]);
      await closeServers();

      acme.rejectFinalize = true;
      await expectLater(
          startServer([_domain], forceRequestCertificate: true),
          throwsA(isA<StateError>().having((e) => e.message, 'message',
              contains('Certificate check error'))));

      // The HTTPS server was running when the check failed:
      for (final port in [letsEncrypt.port, letsEncrypt.securePort]) {
        final socket =
            await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
        await socket.close();
      }
    });

    test('handles a mixed-case domain', () async {
      const mixedCase =
          Domain(name: 'WWW.Example.com', email: 'admin@example.com');
      await startServer([mixedCase]);
      expect(acme.certificatesIssued, equals(1));

      final (body, _) = await get(https(mixedCase));
      expect(body, equals('Hello www.example.com'));
    });
  });

  group('requestCertificate', () {
    Future<void> expectFailure(Matcher message) async {
      final server = await serveChallenges();
      try {
        await expectLater(
            letsEncrypt.requestCertificate(_domain),
            throwsA(isA<StateError>()
                .having((e) => e.message, 'message', message)));
      } finally {
        await server.close(force: true);
      }
      expect(letsEncrypt.getChallengeToken(_domain.name), isNull);
    }

    test('recovers when the client initialization fails', () async {
      acme.breakNextAccountRequest = true;
      final server = await serveChallenges();
      try {
        expect(await letsEncrypt.requestCertificate(_domain), isTrue);
      } finally {
        await server.close(force: true);
      }
      expect(logs, contains(contains('Trying initialization fallback')));
    });

    test('fails without an account', () async {
      acme.rejectAccounts = true;
      await expectFailure(contains("Can't initialize account"));
    });

    test('fails without an ACME directory', () async {
      await acme.close();
      await expectLater(
          letsEncrypt.requestCertificate(_domain),
          throwsA(isA<StateError>().having((e) => e.message, 'message',
              contains("Can't load the ACME directory"))));
      await acme.start();
    });

    test('fails when the order is rejected', () async {
      acme.rejectNewOrder = true;
      await expectFailure(contains("Can't create order"));
    });

    test('fails without authorizations', () async {
      acme.emptyAuthorizations = true;
      await expectFailure(contains("Can't get Authorization"));
    });

    test('fails when the order is not ready', () async {
      acme.orderNotReady = true;
      await expectFailure(contains('Order not ready'));
    });

    test('fails when finalization is rejected', () async {
      acme.rejectFinalize = true;
      await expectFailure(contains('Error finalizing order'));
    });

    test('fails when the certificate download fails', () async {
      acme.rejectCertificate = true;
      await expectFailure(contains('Error getting certificates'));
    });

    test('fails the self test when the challenge is not served', () async {
      await expectLater(
          letsEncrypt.requestCertificate(_domain),
          throwsA(isA<StateError>().having(
              (e) => e.message, 'message', contains('Self HTTP test not OK'))));
      expect(letsEncrypt.getChallengeToken(_domain.name), isNull);
    });

    for (final (served, log) in [
      ('', 'Self test: EMPTY'),
      ('wrong', 'Self test: ERROR')
    ]) {
      test('fails the self test when "$served" is served', () async {
        final server = await serve(
            (request) => Response.ok(served), '127.0.0.1', letsEncrypt.port);
        try {
          await expectLater(
              letsEncrypt.requestCertificate(_domain), throwsStateError);
        } finally {
          await server.close(force: true);
        }
        expect(logs, contains(contains(log)));
      });
    }
  });

  group('checkCertificate', () {
    test('requests a certificate when HTTPS is not available', () async {
      final server = await serveChallenges();
      try {
        expect(
            await letsEncrypt.checkCertificate(_domain,
                requestCertificate: true,
                retryInterval: const Duration(milliseconds: 1)),
            equals(CheckCertificateStatus.okRefreshed));
      } finally {
        await server.close(force: true);
      }
    });

    test('reports an error when the request fails', () async {
      acme.rejectNewOrder = true;
      expect(
          await letsEncrypt.checkCertificate(_domain,
              requestCertificate: true,
              maxRetries: 1,
              retryInterval: const Duration(milliseconds: 1)),
          equals(CheckCertificateStatus.error));
    });

    test('rejects a certificate close to expiration', () async {
      await startServer([_domain]);
      letsEncrypt.minCertificateValidityTime = const Duration(days: 365);

      expect(
          await letsEncrypt.isDomainHttpsOK(_domain, maxRetries: 1), isFalse);
      expect(logs, contains(contains('certificate short validity period')));
    });

    test('rejects a non-200 response', () async {
      await startServer([_domain]);
      expect(
          await letsEncrypt
              .getURL(https(_domain, '/.well-known/acme-challenge/x')),
          isNull);
    });

    test('rejects an expired certificate', () async {
      final expired = selfSignedCertificate(_domain.name, days: -1);
      final context = SecurityContext()
        ..useCertificateChainBytes(utf8.encode(expired.certificatePEM))
        ..usePrivateKeyBytes(utf8.encode(expired.privateKeyPEM));
      final server = await serve((request) => Response.ok('expired'),
          '127.0.0.1', letsEncrypt.securePort,
          securityContext: context);
      try {
        expect(await letsEncrypt.isUrlOK(https(_domain)), isFalse);
        expect(
            await letsEncrypt.getURL(https(_domain), checkCertificate: false),
            equals('expired'));
      } finally {
        await server.close(force: true);
      }
      expect(logs, contains(contains('certificate expired')));
    });

    test('accepts bad certificates only in staging', () async {
      await startServer([_domain]);
      final (_, certificate) = await get(https(_domain));

      expect(
          letsEncrypt.badCertificateCallback(certificate!, _domain.name, 443),
          isTrue);
      final production =
          LetsEncrypt(letsEncrypt.certificatesHandler, production: true);
      expect(production.badCertificateCallback(certificate, _domain.name, 443),
          isFalse);
      expect(production.apiBaseURL, isNot(contains('staging')));
    });
  });

  group('deprecated API', () {
    test('startSecureServer', () async {
      // ignore: deprecated_member_use_from_same_package
      final started = await letsEncrypt.startSecureServer(
          (request) => Response.ok('Hello'), {_domain.name: _domain.email});
      servers.addAll(started);

      expect(started, hasLength(2));
      expect(acme.certificatesIssued, equals(1));
    });

    test('isWellknownPath', () {
      // ignore: deprecated_member_use_from_same_package
      expect(LetsEncrypt.isWellknownPath('/.well-known/x'), isTrue);
    });
  });
}
