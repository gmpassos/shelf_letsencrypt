// ignore_for_file: avoid_catches_without_on_clauses

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:acme_client/acme_client.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_letsencrypt/src/check_certificate_status.dart';

import 'certs_handler.dart';
import 'domain.dart';
import 'logging.dart';

/// Let's Encrypt certificate tool.
class LetsEncrypt {
  LetsEncrypt(this.certificatesHandler, {this.production = false, Logging? log})
      : logger = Logger(log);

  Logger logger;

  /// Returns `true` if [path] starts with `/.well-known/`.
  static bool isWellKnownPath(String path) => path.startsWith('/.well-known/');

  @Deprecated('Use `isWellKnownPath`')
  static bool isWellknownPath(String path) => isWellKnownPath(path);

  /// Returns `true` if [path] is an `ACME` request path.
  ///
  /// Usually a path starting with: `/.well-known/`
  static bool isACMEPath(String path) =>
      path.startsWith('/.well-known/acme-challenge/');

  /// Returns `true` if [path] is a self check path.
  static bool isSelfCheckPath(String path) =>
      path.startsWith('/.well-known/check/');

  /// The certificate handler to use.
  final CertificatesHandler certificatesHandler;

  /// If `true` uses production API.
  final bool production;

  /// Returns the Let's Encrypt API base URL in use.
  String get apiBaseURL => production
      ? 'https://acme-v02.api.letsencrypt.org'
      : 'https://acme-staging-v02.api.letsencrypt.org';

  final Map<String, String> _challengesTokens = <String, String>{};

  /// Returns a challenge toke for [cn] (if one is being executed).
  String? getChallengeToken(String cn) => _challengesTokens[cn];

  static final RegExp _regexpContactMethodPrefix = RegExp(r'^\w+:');

  /// Performs an `ACME` challenge. Default to `HTTP-1`.
  /// - [cn] is the domain to request a certificate.
  /// - [contacts] is the list of domain contacts, usually emails.
  /// - [accountPrivateKeyPem] is the account private key in PEM format.
  /// - [accountPublicKeyPem] is the account public key in PEM format.
  /// - [domainCSR] is the domain Certificate Signing Request in PEM format.
  ///
  /// Used by [requestCertificate].
  Future<List<String>> doACMEChallenge(
    int port,
    String cn,
    List<String> contacts,
    String accountPrivateKeyPem,
    String accountPublicKeyPem,
    String domainCSR,
  ) async {
    final contactsWithMethod = contacts
        .map((e) => !e.startsWith(_regexpContactMethodPrefix) && e.contains('@')
            ? 'mailto:$e'
            : e)
        .toList();

    logger.info(
        'apiBaseURL: $apiBaseURL ; cn: $cn ; contacts: $contactsWithMethod');

    final client = AcmeClient(
      apiBaseURL,
      accountPrivateKeyPem,
      accountPublicKeyPem,
      true,
      contactsWithMethod,
    );

    await _initializeClient(client, cn);

    final order = Order(identifiers: [Identifiers(type: 'dns', value: cn)]);
    logger.info('Order for $cn: ${order.toJson()}');

    final newOrder = await client.order(order);

    logger.info('Fetching authorization data for order...');

    final auth = await client.getAuthorization(newOrder!);
    if (auth == null || auth.isEmpty) {
      throw StateError("Can't get Authorization");
    }

    final mainAuth = auth.first;
    final challengeData = mainAuth.getHttpDcvData();

    _challengesTokens[cn] = challengeData.fileContent;

    logger.info('Self test challenge... ${challengeData.toJson()}');

    final selfTestOK = await _selfChallengeTest(port, client, challengeData);
    if (!selfTestOK) {
      throw StateError('Self HTTP test not OK!');
    }

    final challenge =
        mainAuth.challenges!.firstWhere((e) => e.type == VALIDATION_HTTP);

    logger.info('Validating challenge: ${challenge.toJson()}');
    final valid = await client.validate(challenge);

    if (!valid) {
      throw StateError('Challenge not valid!');
    }

    logger.info('Authorization successful!');

    await Future.delayed(const Duration(seconds: 1), () {});

    final ready = await client.isReady(newOrder);
    if (!ready) {
      throw StateError('Order not ready!');
    }

    logger.info('Finalizing order...');
    final persistent = await client.finalizeOrder(newOrder, domainCSR);

    if (persistent == null) {
      throw StateError('Error finalizing order!');
    }

    logger.info('Getting certificates...');
    final certs = await client.getCertificate(persistent);

    _challengesTokens.remove(cn);

    if (certs == null || certs.isEmpty) {
      throw StateError('Error getting certificates!');
    }

    logger.info('Certificates:\n>> ${certs.join('\n>> ')}');

    return certs;
  }

  Future<bool> _initializeClient(AcmeClient client, String cn) async {
    try {
      await client.init();
      return true;
    } catch (e, s) {
      logger.error(e, s);
      await _initializeClientFallback(client, cn);
      return true;
    }
  }

  Future<void> _initializeClientFallback(AcmeClient client, String cn) async {
    logger.info('Trying initialization fallback...');

    Account? account;
    try {
      account = await client.getAccount(createIfnotExists: false);
    } catch (e, s) {
      logger.error(e, s);
    }

    try {
      if (account == null) {
        logger.info('Creating account...');
        account = await client.createAccount();
      }
    } catch (e, s) {
      logger.error(e, s);
    }

    if (account == null) {
      throw StateError("Can't initialize account for domain: $cn");
    }
  }

  Future<bool> _selfChallengeTest(
      int httpPort, AcmeClient client, HttpDcvData challengeData) async {
    var url = challengeData.fileName;
    if (!url.startsWith('http:') && !url.startsWith('https:')) {
      final idx = url.indexOf(':/');
      if (idx >= 0) {
        final schema = url.substring(0, idx);
        var rest = url.substring(idx);
        rest = rest.replaceFirst(RegExp('^/+'), '');
        url = '$schema://${rest.replaceAll('//', '/')}';
      } else {
        var rest = url.replaceFirst(RegExp('^/+'), '');
        rest = rest.replaceFirst(RegExp('/'), ':$httpPort/');
        rest = rest.replaceAll('//', '/');
        url = 'http://$rest';
      }
    }

    // if (port != 80)
    // {
    //   // patch the port no. into the request.
    //   url.replaceFirst(RegExp(), to)
    // }

    logger.info('Self test URL: $url');

    String? content;
    try {
      content = await getURL(Uri.parse(url));
    } catch (e, s) {
      logger.error('Self test request error for URL: $url', e, s);
      return false;
    }

    if (content == null || content.isEmpty) {
      logger.info('Self test: EMPTY');
      return false;
    }

    final match = content.trim() == challengeData.fileContent;

    if (match) {
      logger.info('Self test: OK');
    } else {
      logger.warning('Self test: ERROR <$content>');
    }

    return match;
  }

  /// A helper method to process a self check [Request].
  ///
  /// See [isSelfCheckPath].
  Response processSelfCheckRequest(Request request) => Response.ok('OK');

  /// A helper method to process an ACME `shelf` [Request].
  ///
  /// See [isACMEPath].
  Response processACMEChallengeRequest(Request request) {
    final host = request.headers['host'] ?? '';
    final cn = host.split(':')[0];

    final challengeToken = getChallengeToken(cn);

    logger.info(
        '''Processing ACME challenge> cn: $cn ; token: $challengeToken > ${request.requestedUri}''');

    if (challengeToken == null) {
      return Response.notFound('No ACME challenge token!');
    }

    return Response.ok(challengeToken);
  }

  /// Starts 2 [HttpServer] instances, one HTTP at [port]
  /// and other HTTPS at [securePort].
  ///
  /// - If [checkCertificate] is `true` will check the current certificate.
  Future<List<HttpServer>> startSecureServer(
      Handler handler, List<Domain> domains,
      {int port = 80,
      int securePort = 443,
      String bindingAddress = '0.0.0.0',
      int? backlog,
      bool shared = false,
      bool checkCertificate = true,
      bool requestCertificate = true,
      bool forceRequestCertificate = false,
      bool loadAllHandledDomains = false}) async {
    logger.info(
        '''Starting server> bindingAddress: $bindingAddress ; port: $port ; domain: $domains''');

    FutureOr<Response> handlerWithChallenge(Request r) {
      final path = r.requestedUri.path;

      if (LetsEncrypt.isWellKnownPath(path)) {
        if (LetsEncrypt.isACMEPath(path)) {
          return processACMEChallengeRequest(r);
        } else if (LetsEncrypt.isSelfCheckPath(path)) {
          return processSelfCheckRequest(r);
        }
      }

      return handler(r);
    }

    final server = await serve(handlerWithChallenge, bindingAddress, port,
        backlog: backlog, shared: shared);

    Future<HttpServer> startSecureServer(SecurityContext securityContext) =>
        serve(handlerWithChallenge, bindingAddress, securePort,
            securityContext: securityContext, backlog: backlog, shared: shared);

    HttpServer? secureServer;

    logger.info('$certificatesHandler');
    logger.info(
        'Handled domains: ${certificatesHandler.listAllHandledDomains()}');

    var securityContext = await certificatesHandler.buildSecurityContext(
        domains,
        loadAllHandledDomains: loadAllHandledDomains);

    logger.info(
        '''securityContext[loadAllHandledDomains: $loadAllHandledDomains]: $securityContext''');

    if (securityContext == null) {
      if (!requestCertificate) {
        throw StateError(
            """No previous SecureContext. Parameter `requestCertificate` is `false`, can't request certificate!""");
      }

      final domainsToCheck = certificatesHandler.listNotHandledDomains(domains);

      logger.info('Requesting certificate for: $domainsToCheck');

      for (final domain in domainsToCheck) {
        final ok = await this.requestCertificate(port, domain);
        if (!ok) {
          throw StateError('Error requesting certificate!');
        }
      }

      securityContext = await certificatesHandler.buildSecurityContext(domains,
          loadAllHandledDomains: loadAllHandledDomains);
      if (securityContext == null) {
        throw StateError(
            '''Error loading SecureContext after successful request of certificate for: $domains''');
      }

      logger.info(
          'Starting secure server> port: $securePort ; domains: $domains');
      secureServer = await startSecureServer(securityContext);
    } else {
      secureServer = await startSecureServer(securityContext);

      if (checkCertificate) {
        logger.info('Checking domains certificates: $domains');

        var refreshedCertificate = false;

        for (final domain in domains) {
          logger.info('Checking certificate for: ${domain.name}');

          final checkCertificateStatus = await this.checkCertificate(
              port, domain,
              requestCertificate: requestCertificate,
              forceRequestCertificate: forceRequestCertificate);

          logger.info('CheckCertificateStatus: $checkCertificateStatus');

          if (checkCertificateStatus.isOkRefreshed) {
            refreshedCertificate = true;
          } else if (checkCertificateStatus.isNotOK) {
            throw StateError(
                '''Certificate check error! Status: $checkCertificateStatus ; domain: ${domain.name}''');
          }
        }

        if (refreshedCertificate) {
          logger.warning('Refreshing SecureContext due new certificate.');
          securityContext = await certificatesHandler.buildSecurityContext(
              domains,
              loadAllHandledDomains: loadAllHandledDomains);
          if (securityContext == null) {
            throw StateError(
                '''Error loading SecureContext after successful certificate check for: ${Domain.toNames(domains)}''');
          }

          logger.warning('Restarting secure server...');
          await secureServer.close(force: true);
          secureServer = await startSecureServer(securityContext);
        }
      }
    }

    return [server, secureServer];
  }

  /// Checks the [domain] certificate.
  Future<CheckCertificateStatus> checkCertificate(int port, Domain domain,
      {bool requestCertificate = false,
      bool forceRequestCertificate = false,
      int maxRetries = 3,
      Duration? retryInterval}) async {
    final domainHttpsOK = await isDomainHttpsOK(domain,
        maxRetries: maxRetries, retryInterval: retryInterval);

    if (domainHttpsOK && !forceRequestCertificate) {
      return CheckCertificateStatus.ok;
    }

    if (!requestCertificate) {
      return CheckCertificateStatus.invalid;
    }

    try {
      final ok = await this.requestCertificate(port, domain);
      return ok
          ? CheckCertificateStatus.okRefreshed
          : CheckCertificateStatus.error;
    } catch (e, s) {
      logger.error(e, s);
      return CheckCertificateStatus.error;
    }
  }

  /// Request a certificate for [domain] using an `ACME` client.
  ///
  /// Calls [doACMEChallenge].
  Future<bool> requestCertificate(int port, Domain domain) async {
    final accountKeyPair = await certificatesHandler.ensureAccountPEMKeyPair();

    await certificatesHandler.ensureDomainPEMKeyPair(domain.name);

    final csr =
        await certificatesHandler.generateCSR(domain.name, domain.email);
    if (csr == null) {
      throw StateError("Can't generate CSR for domain: $domain");
    }

    final certs = await doACMEChallenge(port, domain.name, [domain.email],
        accountKeyPair.privateKeyPEM, accountKeyPair.publicKeyPEM, csr);

    final ok = await certificatesHandler.saveSignedCertificateChain(
        domain.name, certs);

    return ok;
  }

  /// The minimal accepted HTTPS certificate validity time
  /// when checking the current certificate validity. Default: 5 days
  /// - See [isDomainHttpsOK].
  Duration minCertificateValidityTime = const Duration(days: 5);

  /// Returns true if [domain] HTTPS is OK.
  Future<bool> isDomainHttpsOK(Domain domain,
      {int maxRetries = 3, Duration? retryInterval}) async {
    if (retryInterval == null) {
      retryInterval = const Duration(seconds: 1);
    } else if (retryInterval.inMilliseconds < 10) {
      retryInterval = const Duration(milliseconds: 10);
    }

    final minCertificateValidityTime = this.minCertificateValidityTime;

    final domainURL =
        Uri.parse('https://${domain.name}/.well-known/check/${DateTime.now()}');

    for (var i = 0; i < maxRetries; ++i) {
      if (i > 0) {
        await Future.delayed(retryInterval, () {});
      }
      final ok = await isUrlOK(domainURL,
          minCertificateValidityTime: minCertificateValidityTime);
      if (ok) {
        return true;
      }
    }

    return false;
  }

  /// Returns `true` if the [url] is OK (performs a request).
  Future<bool> isUrlOK(Uri url, {Duration? minCertificateValidityTime}) async {
    try {
      final body = await getURL(
        url,
        minCertificateValidityTime: minCertificateValidityTime,
      );
      return body != null;
    } catch (_) {
      return false;
    }
  }

  /// Performs a HTTP request for [url]. Returns a [String] with the body if OK.
  Future<String?> getURL(Uri url,
      {Duration? minCertificateValidityTime,
      bool checkCertificate = true,
      bool log = true}) async {
    final client = HttpClient()
      ..badCertificateCallback = badCertificateCallback;

    final request = await client.getUrl(url);
    final response = await request.close();

    final ok = response.statusCode == 200;
    if (!ok) {
      return null;
    }

    final certificate = response.certificate;
    if (certificate != null && checkCertificate) {
      final now = DateTime.now();
      final endValidity = certificate.endValidity;
      final timeLeftInValidity = endValidity.difference(now);

      if (timeLeftInValidity.isNegative) {
        logger.warning(
            'URL `${url.scheme}://${url.host}` certificate expired> timeLeftInValidity: ${timeLeftInValidity.inHours} h ; endValidity: $endValidity ; now: $now');
        return null;
      }

      if (minCertificateValidityTime != null &&
          timeLeftInValidity < minCertificateValidityTime) {
        logger.warning(
            'URL `${url.scheme}://${url.host}` certificate short validity period> timeLeftInValidity: ${timeLeftInValidity.inHours} h ; minCertificateValidityTime: ${minCertificateValidityTime.inHours} h ; endValidity: $endValidity ; now: $now');
        return null;
      }
    }

    final data = await response.transform(const Utf8Decoder()).toList();
    final body = data.join();

    return body;
  }

  /// Handles a bad certificate triggered by [HttpClient].
  /// Should return `true` to accept a bad certificate (like a self-signed).
  ///
  /// Defaults to ![production], since in [production] the staging certificate
  /// is invalid.
  bool badCertificateCallback(X509Certificate cert, String host, int port) =>
      !production;
}
