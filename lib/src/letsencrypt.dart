import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:acme_client/acme_client.dart';
import 'package:multi_domain_secure_server/multi_domain_secure_server.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';

import 'certs_handler.dart';
import 'check_certificate_status.dart';
import 'domain.dart';
import 'logging.dart';
import 'pending_dns_persist_request.dart';

/// The ACME challenge workflow used by [LetsEncrypt].
enum LetsEncryptChallengeType {
  /// Serve an `http-01` response from `/.well-known/acme-challenge/...`.
  http,

  /// Publish a persistent `dns-persist-01` TXT record.
  dnsPersist,
}

/// Publishes the TXT record required for a `dns-persist-01` challenge.
///
/// `shelf_letsencrypt` can satisfy `http-01` itself because it controls the
/// HTTP server. DNS publication is environment-specific, so callers must wire
/// this callback to their DNS provider or automation.
typedef DnsPersistChallengePublisher = FutureOr<void> Function(
    String domainName, DnsPersistChallengeProof proof);

/// Let's Encrypt certificate tool.
class LetsEncrypt {
  final int port;
  final int securePort;
  final String bindingAddress;
  final bool selfTest;
  final String? acmeDirectoryUrl;
  final LetsEncryptChallengeType challengeType;
  final DnsPersistChallengePublisher? dnsPersistChallengePublisher;
  final AcmeConnection? acmeConnection;

  LetsEncrypt(this.certificatesHandler,
      {this.port = 80,
      this.securePort = 443,
      this.bindingAddress = '0.0.0.0',
      this.production = false,
      this.selfTest = true,
      this.acmeDirectoryUrl,
      this.challengeType = LetsEncryptChallengeType.http,
      this.dnsPersistChallengePublisher,
      this.acmeConnection,
      Logging? log})
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
  String get apiBaseURL =>
      acmeDirectoryUrl ??
      (production
          ? 'https://acme-v02.api.letsencrypt.org'
          : 'https://acme-staging-v02.api.letsencrypt.org');

  final Map<String, String> _challengesTokens = <String, String>{};

  /// Returns a challenge toke for [cn] (if one is being executed).
  String? getChallengeToken(String cn) => _challengesTokens[cn];

  static final RegExp _regexpContactMethodPrefix = RegExp(r'^\w+:');

  /// Performs an `ACME` challenge using the configured [challengeType].
  /// - [cn] is the domain to request a certificate.
  /// - [contacts] is the list of domain contacts, usually emails.
  /// - [accountPrivateKeyPem] is the account private key in PEM format.
  /// - [accountPublicKeyPem] is the account public key in PEM format.
  /// - [domainCSR] is the domain Certificate Signing Request in PEM format.
  ///
  /// Used by [requestCertificate].
  Future<List<String>> doACMEChallenge(
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

    final accountCredentials = AcmeAccountCredentials(
      privateKeyPem: accountPrivateKeyPem,
      publicKeyPem: accountPublicKeyPem,
      acceptTerms: true,
      contacts: contactsWithMethod,
    );
    final certificateCredentials = CertificateCredentials(
      privateKeyPem: '',
      publicKeyPem: '',
      csrPem: domainCSR,
      identifiers: [DomainIdentifier(cn)],
    );
    try {
      final account = await _fetchOrCreateAccount(accountCredentials, cn);
      final identifier = DomainIdentifier(cn);

      switch (challengeType) {
        case LetsEncryptChallengeType.http:
          return _doHttpChallenge(
            account: account,
            cn: cn,
            identifier: identifier,
            certificateCredentials: certificateCredentials,
          );
        case LetsEncryptChallengeType.dnsPersist:
          return _doDnsPersistChallenge(
            account: account,
            cn: cn,
            identifier: identifier,
            certificateCredentials: certificateCredentials,
          );
      }
    } catch (e, s) {
      logger.error(e, s);
      rethrow;
    } finally {
      _challengesTokens.remove(cn);
    }
  }

  Future<Account> _fetchOrCreateAccount(
    AcmeAccountCredentials credentials,
    String cn,
  ) async {
    try {
      return await Account.fetch(credentials, connection: _connection);
    } catch (e, s) {
      logger.warning('Failed to fetch ACME account, trying create', e, s);
    }

    try {
      return await Account.create(credentials, connection: _connection);
    } catch (e, s) {
      logger.error('Failed to create ACME account for domain: $cn', e, s);
      rethrow;
    }
  }

  Future<List<String>> _doHttpChallenge({
    required Account account,
    required String cn,
    required DomainIdentifier identifier,
    required CertificateCredentials certificateCredentials,
  }) async {
    final order = await account.createOrderForHttp(identifiers: [identifier]);
    final authorization = await order.getAuthorization(identifier);
    final challenge = authorization.getChallenge();
    final proof = challenge.buildProof();

    _challengesTokens[cn] = proof.wellKnownChallengeFileContent;

    logger.info(
      'Serving http-01 challenge for $cn at ${proof.pathToWellKnownChallenge}',
    );

    return _validateFinalizeAndFetch(
      cn: cn,
      challengeSelfTest: () => challenge.selfTest(),
      challengeValidate: () => challenge.validate(),
      orderIsReady: () => order.isReady(),
      orderFinalize: () => order.finalize(certificateCredentials),
      orderGetCertificates: () => order.getCertificates(),
    );
  }

  Future<List<String>> _doDnsPersistChallenge({
    required Account account,
    required String cn,
    required DomainIdentifier identifier,
    required CertificateCredentials certificateCredentials,
  }) async {
    final publish = dnsPersistChallengePublisher;
    final order = await account.createOrderForDnsPersist(
      identifiers: [identifier],
    );
    final authorization = await order.getAuthorization(identifier);
    final challenge = authorization.getChallenge();
    final proof = challenge.buildProof();

    if (publish == null) {
      logger.info(
        'No dns-persist-01 publisher configured for $cn; '
        'validating existing DNS record: ${proof.toBindString()}',
      );
    } else {
      logger.info(
        'Publishing dns-persist-01 challenge for $cn: ${proof.toBindString()}',
      );
      await publish(cn, proof);
    }

    return _validateFinalizeAndFetch(
      cn: cn,
      challengeSelfTest: () => challenge.selfTest(),
      challengeValidate: () => challenge.validate(),
      orderIsReady: () => order.isReady(),
      orderFinalize: () => order.finalize(certificateCredentials),
      orderGetCertificates: () => order.getCertificates(),
    );
  }

  /// Prepares a manual `dns-persist-01` flow for [domain].
  ///
  /// This is intended for environments where a human operator must publish the
  /// TXT record before validation continues. The returned [PendingDnsPersistRequest]
  /// contains the record to publish and a [PendingDnsPersistRequest.complete]
  /// callback that should be invoked only after the record is visible in DNS.
  Future<PendingDnsPersistRequest> prepareDnsPersistCertificateRequest(
    Domain domain,
  ) async {
    final accountKeyPair = await certificatesHandler.ensureAccountPEMKeyPair();
    await certificatesHandler.ensureDomainPEMKeyPair(domain.name);

    final csr =
        await certificatesHandler.generateCSR(domain.name, domain.email);
    if (csr == null) {
      throw StateError("Can't generate CSR for domain: $domain");
    }

    final accountCredentials = AcmeAccountCredentials(
      privateKeyPem: accountKeyPair.privateKeyPEM,
      publicKeyPem: accountKeyPair.publicKeyPEM,
      acceptTerms: true,
      contacts: ['mailto:${domain.email}'],
    );
    final certificateCredentials = CertificateCredentials(
      privateKeyPem: '',
      publicKeyPem: '',
      csrPem: csr,
      identifiers: [DomainIdentifier(domain.name)],
    );
    final account =
        await _fetchOrCreateAccount(accountCredentials, domain.name);
    final identifier = DomainIdentifier(domain.name);
    final order = await account.createOrderForDnsPersist(
      identifiers: [identifier],
    );
    final authorization = await order.getAuthorization(identifier);
    final challenge = authorization.getChallenge();
    final proof = challenge.buildProof();

    logger.info(
      'Prepared dns-persist-01 challenge for ${domain.name}: ${proof.toBindString()}',
    );

    return PendingDnsPersistRequest.internal(
      domainName: domain.name,
      proof: proof,
      complete: ({bool forceRequestCertificate = false}) async {
        if (!forceRequestCertificate &&
            certificatesHandler.isHandledDomainCertificate(domain.name)) {
          logger.info(
            'Certificate for ${domain.name} is already stored and valid.',
          );
          return true;
        }

        final certs = await _validateFinalizeAndFetch(
          cn: domain.name,
          challengeSelfTest: () => challenge.selfTest(),
          challengeValidate: () => challenge.validate(),
          orderIsReady: () => order.isReady(),
          orderFinalize: () => order.finalize(certificateCredentials),
          orderGetCertificates: () => order.getCertificates(),
        );

        return certificatesHandler.saveSignedCertificateChain(
          domain.name,
          certs,
        );
      },
    );
  }

  Future<List<String>> _validateFinalizeAndFetch({
    required String cn,
    required Future<bool> Function() challengeSelfTest,
    required Future<bool> Function() challengeValidate,
    required Future<bool> Function() orderIsReady,
    required Future<void> Function() orderFinalize,
    required Future<List<String>> Function() orderGetCertificates,
  }) async {
    if (selfTest) {
      final selfTestOK = await challengeSelfTest();
      if (!selfTestOK) {
        throw StateError('Challenge self-test not OK for $cn');
      }
    }

    final valid = await challengeValidate();
    if (!valid) {
      throw StateError('Challenge not valid - check your firewall and DNS!');
    }

    logger.info('Authorization successful!');

    final ready = await _waitUntilOrderReady(orderIsReady);
    if (!ready) {
      throw StateError('Order not ready!');
    }

    logger.info('Finalizing order...');
    await orderFinalize();

    logger.info('Getting certificates...');
    final certs = await orderGetCertificates();
    if (certs.isEmpty) {
      throw StateError('Error getting certificates!');
    }

    logger.info('Certificates:\n>> ${certs.join('\n>> ')}');
    return certs;
  }

  Future<bool> _waitUntilOrderReady(
    Future<bool> Function() orderIsReady, {
    int maxAttempts = 5,
  }) async {
    for (var attempt = 0; attempt < maxAttempts; attempt++) {
      if (await orderIsReady()) {
        return true;
      }
      if (attempt + 1 < maxAttempts) {
        await Future.delayed(const Duration(seconds: 1), () {});
      }
    }
    return false;
  }

  AcmeConnection get _connection =>
      acmeConnection ??
      AcmeConnection(
        baseUrl: acmeDirectoryUrl ??
            (production
                ? AcmeConnection.letsEncryptDirectoryUrl
                : AcmeConnection.letsEncryptStagingDirectoryUrl),
        logger: _logAcme,
      );

  void _logAcme(
    AcmeLogLevel level,
    String message, {
    Object? error,
    StackTrace? stackTrace,
  }) {
    switch (level) {
      case AcmeLogLevel.debug:
        logger.info(message, stackTrace);
        break;
      case AcmeLogLevel.warning:
        logger.warning(message, error, stackTrace);
        break;
      case AcmeLogLevel.error:
        logger.error(message, error, stackTrace);
        break;
    }
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

  /// Use [startServer].
  @Deprecated('Use `startServer`. Will be removed at v2.1.0')
  Future<List<HttpServer>> startSecureServer(
      Handler handler, Map<String, String> domainsAndEmails,
      {int? backlog,
      bool shared = false,
      bool checkCertificate = true,
      bool requestCertificate = true,
      bool forceRequestCertificate = false,
      bool loadAllHandledDomains = false}) async {
    final domains = <Domain>[];

    for (var entry in domainsAndEmails.entries) {
      domains.add(Domain(name: entry.key, email: entry.value));
    }

    var servers = await startServer(handler, domains,
        backlog: backlog,
        shared: shared,
        checkCertificate: checkCertificate,
        requestCertificate: requestCertificate,
        forceRequestCertificate: forceRequestCertificate,
        loadAllHandledDomains: loadAllHandledDomains);

    return [servers.http, servers.https];
  }

  /// Starts 2 [HttpServer] instances, one HTTP at [port]
  /// and other HTTPS at [securePort].
  ///
  /// - If [checkCertificate] is `true`, will check the current certificates.
  /// - if [requestCertificate] is `true` then we will  acquire/renew the certificates
  ///   as needed.
  /// - If [forceRequestCertificate] is `true` then we will force the acquisition
  ///   of a new certificates.
  ///
  /// *WARNINGS:*
  /// - *The Lets Encrypt CA has VERY tight rate limits
  ///   on certificate acquisition. If you breach them you will not be able to
  ///   acquire a new production certificate for 168 hours!!!*
  /// - *Only use `requestCertificate: true` or `forceRequestCertificate: true`
  ///   if you are certain that you won't make unnecessary certificate requests.*
  Future<({HttpServer http, HttpServer https})> startServer(
      Handler handler, List<Domain> domains,
      {int? backlog,
      bool shared = false,
      bool v6Only = false,
      bool checkCertificate = true,
      bool requestCertificate = true,
      bool forceRequestCertificate = false,
      bool loadAllHandledDomains = false}) async {
    var invalidDomains = domains.where((d) => !d.isValidName).toList();

    if (invalidDomains.isNotEmpty) {
      logger
          .info("Ignoring invalid domains: ${Domain.toNames(invalidDomains)}");

      domains.removeWhere((d) => !d.isValidName);
    }

    if (domains.isEmpty) {
      throw ArgumentError("Empty `domains`! No valid domain provided.");
    }

    logger.info(
        "Starting server> bindingAddress: $bindingAddress ; port: $port ; domain: $domains");

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

    Future<HttpServer> startSecureServer(
        Map<String, SecurityContext> securityContexts,
        {int? backlog,
        bool v6Only = false,
        bool shared = false}) async {
      var defaultSecurityContext = securityContexts['*'] ??
          securityContexts.entries.firstOrNull?.value ??
          (throw ArgumentError(
              "Can't define `defaultSecurityContext`> null `defaultSecurityContext` and empty `securityContexts`"));

      var hasMultipleDomains = securityContexts.length > 1;

      if (hasMultipleDomains ||
              v6Only // `shelf` doesn't provide parameter `v6Only`
          ) {
        logger.info(
            '''Starting secure server with `MultiDomainSecureServer`> domains: ${securityContexts.keys.toList()}''');

        var secureServer = await MultiDomainSecureServer.bind(
          bindingAddress,
          securePort,
          backlog: backlog ?? 0,
          v6Only: v6Only,
          shared: shared,
          requiresHandshakesWithHostname: true,
          defaultSecureContext: defaultSecurityContext,
          securityContextResolver: (hostname) => securityContexts[hostname],
        );

        var httpServer = secureServer.asHttpServer();

        serveRequests(httpServer, handlerWithChallenge);

        return httpServer;
      } else {
        return serve(
          handlerWithChallenge,
          bindingAddress,
          securePort,
          securityContext: defaultSecurityContext,
          backlog: backlog,
          shared: shared,
        );
      }
    }

    HttpServer? secureServer;

    logger.info('$certificatesHandler');
    logger.info(
        'Handled domains: ${certificatesHandler.listAllHandledDomains()}');

    var securityContexts = await certificatesHandler.buildSecurityContexts(
        domains,
        allowUnresolvedDomain: false,
        loadAllHandledDomains: loadAllHandledDomains);

    logger.info(
        '''securityContext[loadAllHandledDomains: $loadAllHandledDomains]: $securityContexts''');

    if (securityContexts == null || securityContexts.isEmpty) {
      if (!requestCertificate) {
        if (securityContexts == null) {
          throw StateError(
              """Can't load all `SecurityContext`s. Parameter `requestCertificate` is `false`, can't request certificates! Domains: ${Domain.toNames(domains)}""");
        } else {
          throw StateError(
              """No previous `SecurityContext`s. Parameter `requestCertificate` is `false`, can't request certificates! Domains: ${Domain.toNames(domains)}""");
        }
      }

      final domainsToCheck = certificatesHandler.listNotHandledDomains(domains);

      logger.info(
          'Requesting certificate for: ${Domain.toNames(domainsToCheck)}');

      for (final domain in domainsToCheck) {
        final ok = await this.requestCertificate(domain);
        if (!ok) {
          throw StateError('Error requesting certificate!');
        }
      }

      securityContexts = await certificatesHandler.buildSecurityContexts(
          domains,
          allowUnresolvedDomain: false,
          loadAllHandledDomains: loadAllHandledDomains);
      if (securityContexts == null || securityContexts.isEmpty) {
        throw StateError(
            '''Error loading SecureContext after successful request of certificates> domainsToCheck: ${Domain.toNames(domainsToCheck)} ; domains: ${Domain.toNames(domains)}''');
      }

      logger.info(
          'Starting secure server> port: $securePort ; domains: $domains');
      secureServer = await startSecureServer(securityContexts,
          backlog: backlog, shared: shared, v6Only: v6Only);
    } else {
      secureServer = await startSecureServer(securityContexts,
          backlog: backlog, shared: shared, v6Only: v6Only);

      if (checkCertificate) {
        logger.info('Checking domains certificates: $domains');

        var refreshedCertificate = false;

        for (final domain in domains) {
          logger.info('Checking certificate for: ${domain.name}');

          final checkCertificateStatus = await this.checkCertificate(domain,
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
          securityContexts = await certificatesHandler.buildSecurityContexts(
              domains,
              loadAllHandledDomains: loadAllHandledDomains);
          if (securityContexts == null || securityContexts.isEmpty) {
            throw StateError(
                '''Error loading SecureContext after successful certificate check for: ${Domain.toNames(domains)}''');
          }

          logger.warning('Restarting secure server...');
          await secureServer.close(force: true);
          secureServer = await startSecureServer(securityContexts,
              backlog: backlog, shared: shared, v6Only: v6Only);
        }
      }
    }

    return (http: server, https: secureServer);
  }

  /// Checks the [domain] certificate.
  Future<CheckCertificateStatus> checkCertificate(Domain domain,
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
      final ok = await this.requestCertificate(domain);
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
  Future<bool> requestCertificate(Domain domain) async {
    if (challengeType == LetsEncryptChallengeType.dnsPersist &&
        dnsPersistChallengePublisher == null &&
        !selfTest) {
      throw StateError(
        'LetsEncrypt configured for dns-persist-01 with no publisher and '
        'selfTest disabled. Provide dnsPersistChallengePublisher, enable '
        'selfTest so the existing TXT record can be verified, or use '
        'prepareDnsPersistCertificateRequest(domain) for a manual flow.',
      );
    }

    final accountKeyPair = await certificatesHandler.ensureAccountPEMKeyPair();

    await certificatesHandler.ensureDomainPEMKeyPair(domain.name);

    final csr =
        await certificatesHandler.generateCSR(domain.name, domain.email);
    if (csr == null) {
      throw StateError("Can't generate CSR for domain: $domain");
    }

    final certs = await doACMEChallenge(domain.name, [domain.email],
        accountKeyPair.privateKeyPEM, accountKeyPair.publicKeyPEM, csr);

    final ok = await certificatesHandler.saveSignedCertificateChain(
        domain.name, certs);

    return ok;
  }

  /// The maximum renewal buffer when checking the current certificate validity.
  ///
  /// The effective buffer is the smaller of this value and one third of the
  /// certificate lifetime. With the default 30 day cap, a 90 day certificate is
  /// renewed with 30 days remaining and a 45 day certificate is renewed with 15
  /// days remaining.
  /// - See [isDomainHttpsOK].
  Duration minCertificateValidityTime = const Duration(days: 30);

  /// Returns true if [domain] HTTPS is OK.
  Future<bool> isDomainHttpsOK(Domain domain,
      {int maxRetries = 3, Duration? retryInterval}) async {
    if (retryInterval == null) {
      retryInterval = const Duration(seconds: 1);
    } else if (retryInterval.inMilliseconds < 10) {
      retryInterval = const Duration(milliseconds: 10);
    }

    final minCertificateValidityTime = this.minCertificateValidityTime;

    final domainURL = Uri.parse(
        'https://${domain.name}:$securePort/.well-known/check/${DateTime.now()}');

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

      if (minCertificateValidityTime != null) {
        final effectiveMinValidityTime = _effectiveMinCertificateValidityTime(
          certificate,
          minCertificateValidityTime,
        );
        if (timeLeftInValidity < effectiveMinValidityTime) {
          logger.warning(
              'URL `${url.scheme}://${url.host}` certificate short validity period> timeLeftInValidity: ${timeLeftInValidity.inHours} h ; minCertificateValidityTime: ${effectiveMinValidityTime.inHours} h ; endValidity: $endValidity ; now: $now');
          return null;
        }
      }
    }

    final data = await response.transform(const Utf8Decoder()).toList();
    final body = data.join();

    return body;
  }

  Duration _effectiveMinCertificateValidityTime(
    X509Certificate certificate,
    Duration maxRenewalBuffer,
  ) {
    final lifetime = certificate.endValidity.difference(
      certificate.startValidity,
    );
    if (lifetime <= Duration.zero) {
      return maxRenewalBuffer;
    }

    final oneThirdLifetime = Duration(
      microseconds: lifetime.inMicroseconds ~/ 3,
    );
    if (oneThirdLifetime <= Duration.zero ||
        oneThirdLifetime > maxRenewalBuffer) {
      return maxRenewalBuffer;
    }

    return oneThirdLifetime;
  }

  /// Handles a bad certificate triggered by [HttpClient].
  /// Should return `true` to accept a bad certificate (like a self-signed).
  ///
  /// Defaults to ![production], since in [production] the staging certificate
  /// is invalid.
  bool badCertificateCallback(X509Certificate cert, String host, int port) =>
      !production;
}
