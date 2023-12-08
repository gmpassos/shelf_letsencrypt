// ignore_for_file: avoid_catches_without_on_clauses

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:acme_client/acme_client.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';

import 'certs_handler.dart';

/// Let's Encrypt certificate tool.
class LetsEncrypt {
  LetsEncrypt(this.certificatesHandler, {this.production = false, this.log});

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

  final void Function(
          String level, Object? message, Object? error, StackTrace? stackTrace)?
      log;

  void _logInfo(Object? m, [StackTrace? stackTrace]) {
    _logImpl('INFO', m, null, stackTrace);
  }

  void _logWarning(Object? m, [Object? error, StackTrace? stackTrace]) {
    _logImpl('WARNING', m, error, stackTrace);
  }

  void _logError(Object? m, [Object? error, StackTrace? stackTrace]) {
    if (error != null && stackTrace == null && error is StackTrace) {
      stackTrace = error;
      if (m is! String) {
        error = m;
        m = null;
      } else {
        error = null;
      }
    }

    _logImpl('ERROR', m, error, stackTrace);
  }

  void _logImpl(
      String level, Object? m, Object? error, StackTrace? stackTrace) {
    if (m == null && error == null && stackTrace == null) {
      return;
    }

    final log = this.log;
    if (log != null) {
      log(level, m, error, stackTrace);
    } else {
      final now = DateTime.now();

      final time = '$now'.padRight(26, '0');

      final levelName = '[$level]'.padRight(9);

      if (m == null && error != null) {
        m = error;
        error = null;
      }

      if (m != null) {
        final message = '$time $levelName LetsEncrypt > $m';
        printToConsole(message);
      }

      if (error != null) {
        printToConsole('[ERROR] $error');
      }

      if (stackTrace != null) {
        printToConsole(stackTrace);
      }
    }
  }

  void printToConsole(Object? o) {
    // ignore: avoid_print
    print(o);
  }

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

    _logInfo(
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
    _logInfo('Order for $cn: ${order.toJson()}');

    final newOrder = await client.order(order);

    _logInfo('Fetching authorization data for order...');

    final auth = await client.getAuthorization(newOrder!);
    if (auth == null || auth.isEmpty) {
      throw StateError("Can't get Authorization");
    }

    final mainAuth = auth.first;
    final challengeData = mainAuth.getHttpDcvData();

    _challengesTokens[cn] = challengeData.fileContent;

    _logInfo('Self test challenge... ${challengeData.toJson()}');

    final selfTestOK = await _selfChallengeTest(client, challengeData);
    if (!selfTestOK) {
      throw StateError('Self HTTP test not OK!');
    }

    final challenge =
        mainAuth.challenges!.firstWhere((e) => e.type == VALIDATION_HTTP);

    _logInfo('Validating challenge: ${challenge.toJson()}');
    final valid = await client.validate(challenge);

    if (!valid) {
      throw StateError('Challenge not valid!');
    }

    _logInfo('Authorization successful!');

    await Future.delayed(const Duration(seconds: 1), () {});

    final ready = await client.isReady(newOrder);
    if (!ready) {
      throw StateError('Order not ready!');
    }

    _logInfo('Finalizing order...');
    final persistent = await client.finalizeOrder(newOrder, domainCSR);

    if (persistent == null) {
      throw StateError('Error finalizing order!');
    }

    _logInfo('Getting certificates...');
    final certs = await client.getCertificate(persistent);

    _challengesTokens.remove(cn);

    if (certs == null || certs.isEmpty) {
      throw StateError('Error getting certificates!');
    }

    _logInfo('Certificates:\n>> ${certs.join('\n>> ')}');

    return certs;
  }

  Future<bool> _initializeClient(AcmeClient client, String cn) async {
    try {
      await client.init();
      return true;
    } catch (e, s) {
      _logError(e, s);
      await _initializeClientFallback(client, cn);
      return true;
    }
  }

  Future<void> _initializeClientFallback(AcmeClient client, String cn) async {
    _logInfo('Trying initialization fallback...');

    Account? account;
    try {
      account = await client.getAccount(createIfnotExists: false);
    } catch (e, s) {
      _logError(e, s);
    }

    try {
      if (account == null) {
        _logInfo('Creating account...');
        account = await client.createAccount();
      }
    } catch (e, s) {
      _logError(e, s);
    }

    if (account == null) {
      throw StateError("Can't initialize account for domain: $cn");
    }
  }

  Future<bool> _selfChallengeTest(
      AcmeClient client, HttpDcvData challengeData) async {
    var url = challengeData.fileName;
    if (!url.startsWith('http:') && !url.startsWith('https:')) {
      final idx = url.indexOf(':/');
      if (idx >= 0) {
        final schema = url.substring(0, idx);
        var rest = url.substring(idx);
        rest = rest.replaceFirst(RegExp('^/+'), '');
        url = '$schema://${rest.replaceAll('//', '/')}';
      } else {
        final rest = url.replaceFirst(RegExp('^/+'), '');
        url = 'http://${rest.replaceAll('//', '/')}';
      }
    }

    _logInfo('Self test URL: $url');

    String? content;
    try {
      content = await getURL(Uri.parse(url));
    } catch (e, s) {
      _logError('Self test request error for URL: $url', e, s);
      return false;
    }

    if (content == null || content.isEmpty) {
      _logInfo('Self test: EMPTY');
      return false;
    }

    final match = content.trim() == challengeData.fileContent;

    if (match) {
      _logInfo('Self test: OK');
    } else {
      _logWarning('Self test: ERROR <$content>');
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

    _logInfo(
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
      Handler handler, Map<String, String> domainsAndEmails,
      {int port = 80,
      int securePort = 443,
      String bindingAddress = '0.0.0.0',
      int? backlog,
      bool shared = false,
      bool checkCertificate = true,
      bool requestCertificate = true,
      bool forceRequestCertificate = false,
      bool loadAllHandledDomains = false}) async {
    _logInfo(
        '''Starting server> bindingAddress: $bindingAddress ; port: $port ; domainAndEmails: $domainsAndEmails''');

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

    final domains = domainsAndEmails.keys.toList();

    _logInfo('$certificatesHandler');
    _logInfo('Handled domains: ${certificatesHandler.listAllHandledDomains()}');

    var securityContext = await certificatesHandler.buildSecurityContext(
        domains,
        loadAllHandledDomains: loadAllHandledDomains);

    _logInfo(
        '''securityContext[loadAllHandledDomains: $loadAllHandledDomains]: $securityContext''');

    if (securityContext == null) {
      if (!requestCertificate) {
        throw StateError(
            """No previous SecureContext. Parameter `requestCertificate` is `false`, can't request certificate!""");
      }

      final domainsToCheck = certificatesHandler.listNotHandledDomains(domains);

      _logInfo('Requesting certificate for: $domainsToCheck');

      for (final domain in domainsToCheck) {
        final domainEmail = domainsAndEmails[domain]!;
        final ok = await this.requestCertificate(domain, domainEmail);
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

      _logInfo('Starting secure server> port: $securePort ; domains: $domains');
      secureServer = await startSecureServer(securityContext);
    } else {
      secureServer = await startSecureServer(securityContext);

      if (checkCertificate) {
        _logInfo('Checking domains certificates: $domains');

        var refreshedCertificate = false;

        for (final domain in domains) {
          final domainEmail = domainsAndEmails[domain]!;

          _logInfo('Checking certificate for: $domain');

          final checkCertificateStatus = await this.checkCertificate(
              domain, domainEmail,
              requestCertificate: requestCertificate,
              forceRequestCertificate: forceRequestCertificate);

          _logInfo('CheckCertificateStatus: $checkCertificateStatus');

          if (checkCertificateStatus.isOkRefreshed) {
            refreshedCertificate = true;
          } else if (checkCertificateStatus.isNotOK) {
            throw StateError(
                '''Certificate check error! Status: $checkCertificateStatus ; domain: $domain''');
          }
        }

        if (refreshedCertificate) {
          _logWarning('Refreshing SecureContext due new certificate.');
          securityContext = await certificatesHandler.buildSecurityContext(
              domains,
              loadAllHandledDomains: loadAllHandledDomains);
          if (securityContext == null) {
            throw StateError(
                '''Error loading SecureContext after successful certificate check for: $domains''');
          }

          _logWarning('Restarting secure server...');
          await secureServer.close(force: true);
          secureServer = await startSecureServer(securityContext);
        }
      }
    }

    return [server, secureServer];
  }

  /// Checks the [domain] certificate.
  Future<CheckCertificateStatus> checkCertificate(String domain, String email,
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
      final ok = await this.requestCertificate(domain, email);
      return ok
          ? CheckCertificateStatus.okRefreshed
          : CheckCertificateStatus.error;
    } catch (e, s) {
      _logError(e, s);
      return CheckCertificateStatus.error;
    }
  }

  /// Request a certificate for [domain] using an `ACME` client.
  ///
  /// Calls [doACMEChallenge].
  Future<bool> requestCertificate(String domain, String email) async {
    final accountKeyPair = await certificatesHandler.ensureAccountPEMKeyPair();

    await certificatesHandler.ensureDomainPEMKeyPair(domain);

    final csr = await certificatesHandler.generateCSR(domain, email);
    if (csr == null) {
      throw StateError("Can't generate CSR for domain: $domain");
    }

    final certs = await doACMEChallenge(domain, [email],
        accountKeyPair.privateKeyPEM, accountKeyPair.publicKeyPEM, csr);

    final ok =
        await certificatesHandler.saveSignedCertificateChain(domain, certs);

    return ok;
  }

  /// The minimal accepted HTTPS certificate validity time
  /// when checking the current certificate validity. Default: 5 days
  /// - See [isDomainHttpsOK].
  Duration minCertificateValidityTime = const Duration(days: 5);

  /// Returns true if [domain] HTTPS is OK.
  Future<bool> isDomainHttpsOK(String domain,
      {int maxRetries = 3, Duration? retryInterval}) async {
    if (retryInterval == null) {
      retryInterval = const Duration(seconds: 1);
    } else if (retryInterval.inMilliseconds < 10) {
      retryInterval = const Duration(milliseconds: 10);
    }

    final minCertificateValidityTime = this.minCertificateValidityTime;

    final domainURL =
        Uri.parse('https://$domain/.well-known/check/${DateTime.now()}');

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
        _logWarning(
            'URL `${url.scheme}://${url.host}` certificate expired> timeLeftInValidity: ${timeLeftInValidity.inHours} h ; endValidity: $endValidity ; now: $now');
        return null;
      }

      if (minCertificateValidityTime != null &&
          timeLeftInValidity < minCertificateValidityTime) {
        _logWarning(
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

/// The [LetsEncrypt.checkCertificate] status.
enum CheckCertificateStatus {
  ok,
  okRefreshed,
  invalid,
  error,
}

extension CheckCertificateStatusExtension on CheckCertificateStatus {
  /// Returns `true` if is `ok` or `okRefreshed`.
  bool get isOK =>
      this == CheckCertificateStatus.ok ||
      this == CheckCertificateStatus.okRefreshed;

  /// Returns: ![isOK]
  bool get isNotOK => !isOK;

  /// Returns `true` if is `okRefreshed`.
  bool get isOkRefreshed => this == CheckCertificateStatus.okRefreshed;
}
