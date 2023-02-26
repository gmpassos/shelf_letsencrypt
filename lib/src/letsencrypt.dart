import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:acme_client/acme_client.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';

import 'certs_handler.dart';

/// Let's Encrypt certificate tool.
class LetsEncrypt {
  /// Returns `true` if [path] starts with `/.well-known/`.
  static bool isWellknownPath(String path) => path.startsWith('/.well-known/');

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

  final void Function(Object?)? log;

  LetsEncrypt(this.certificatesHandler, {this.production = false, this.log});

  void _logMsg(Object? m, [StackTrace? stackTrace]) {
    if (m == null) return;

    var log = this.log;
    if (log != null) {
      log(m);
      if (stackTrace != null) {
        log(stackTrace);
      }
    } else {
      print(m);
      if (stackTrace != null) {
        print(stackTrace);
      }
    }
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
    final String accountPrivateKeyPem,
    final String accountPublicKeyPem,
    final String domainCSR,
  ) async {
    var contactsWithMethod = contacts
        .map((e) => !e.startsWith(_regexpContactMethodPrefix) && e.contains('@')
            ? 'mailto:$e'
            : e)
        .toList();

    _logMsg(
        'apiBaseURL: $apiBaseURL ; cn: $cn ; contacts: $contactsWithMethod');

    var client = AcmeClient(
      apiBaseURL,
      accountPrivateKeyPem,
      accountPublicKeyPem,
      true,
      contactsWithMethod,
    );

    await _initializeClient(client, cn);

    var order = Order(identifiers: [Identifiers(type: 'dns', value: cn)]);
    _logMsg('Order for $cn: ${order.toJson()}');

    var newOrder = await client.order(order);

    _logMsg('Fetching authorization data for order...');

    var auth = await client.getAuthorization(newOrder!);
    if (auth == null || auth.isEmpty) {
      throw StateError("Can't get Authorization");
    }

    var mainAuth = auth.first;
    var challengeData = mainAuth.getHttpDcvData();

    _challengesTokens[cn] = challengeData.fileContent;

    _logMsg('Self test challenge...');

    var selfTestOK = await _selfChallengeTest(client, challengeData);
    if (!selfTestOK) {
      throw StateError("Self HTTP test not OK!");
    }

    var challenge =
        mainAuth.challenges!.firstWhere((e) => e.type == VALIDATION_HTTP);

    _logMsg('Validating challenge: ${challenge.toJson()}');
    var valid = await client.validate(challenge);

    if (!valid) {
      throw StateError("Challenge not valid!");
    }

    _logMsg('Authorization successful!');

    await Future.delayed(Duration(seconds: 1));

    var ready = await client.isReady(newOrder);
    if (!ready) {
      throw StateError("Order not ready!");
    }

    _logMsg('Finalizing order...');
    var persistent = await client.finalizeOrder(newOrder, domainCSR);

    if (persistent == null) {
      throw StateError("Error finalizing order!");
    }

    _logMsg('Getting certificates...');
    var certs = await client.getCertificate(persistent);

    _challengesTokens.remove(cn);

    if (certs == null || certs.isEmpty) {
      throw StateError("Error getting certificates!");
    }

    _logMsg(certs);

    return certs;
  }

  Future<bool> _initializeClient(AcmeClient client, String cn) async {
    try {
      await client.init();
      return true;
    } catch (e, s) {
      _logMsg(e, s);
      await _initializeClientFallback(client, cn);
      return true;
    }
  }

  Future<void> _initializeClientFallback(AcmeClient client, String cn) async {
    _logMsg('Trying initialization fallback...');

    Account? account;
    try {
      account = await client.getAccount(createIfnotExists: false);
    } catch (e, s) {
      _logMsg(e, s);
    }

    try {
      if (account == null) {
        _logMsg('Creating account...');
        account = await client.createAccount();
      }
    } catch (e) {
      _logMsg(e);
    }

    if (account == null) {
      throw StateError("Can't initialize account for domain: $cn");
    }
  }

  Future<bool> _selfChallengeTest(
      AcmeClient client, HttpDcvData challengeData) async {
    var url = challengeData.fileName;
    if (!url.startsWith('http:') && !url.startsWith('https:')) {
      var idx = url.indexOf(':/');
      if (idx >= 0) {
        var schema = url.substring(0, idx);
        var rest = url.substring(idx);
        rest = rest.replaceFirst(RegExp(r'^/+'), '');
        url = '$schema://${rest.replaceAll('//', '/')}';
      } else {
        var rest = url.replaceFirst(RegExp(r'^/+'), '');
        url = 'http://${rest.replaceAll('//', '/')}';
      }
    }

    var content = await getURL(Uri.parse(url));

    if (content == null || content.isEmpty) {
      return false;
    }

    var match = content.trim() == challengeData.fileContent;
    return match;
  }

  /// A helper method to process a self check [Request].
  ///
  /// See [isSelfCheckPath].
  Response processSelfCheckRequest(Request request) {
    return Response.ok('OK');
  }

  /// A helper method to process an ACME `shelf` [Request].
  ///
  /// See [isACMEPath].
  Response processACMEChallengeRequest(Request request) {
    var host = request.headers['host'] ?? '';
    var cn = host.split(':')[0];

    var challengeToken = getChallengeToken(cn);

    _logMsg(
        'Processing ACME challenge> cn: $cn ; token: $challengeToken > ${request.requestedUri}');

    if (challengeToken == null) {
      return Response.notFound('No ACME challenge token!');
    }

    return Response.ok(challengeToken);
  }

  /// Starts 2 [HttpServer] instances, one HTTP at [port] and other HTTPS at [securePort].
  ///
  /// - If [checkCertificate] is `true` will check the current certificate.
  Future<List<HttpServer>> startSecureServer(
      Handler handler, Map<String, String> domainsAndEmails,
      {int port = 80,
      int securePort = 443,
      bindingAddress = '0.0.0.0',
      int? backlog,
      bool shared = false,
      bool checkCertificate = true,
      bool requestCertificate = true,
      bool forceRequestCertificate = false,
      bool loadAllHandledDomains = false}) async {
    _logMsg('Starting server: $bindingAddress:$port');

    _logMsg(
        'Starting server> port: $port ; domainAndEmails: $domainsAndEmails');

    FutureOr<Response> handlerWithChallenge(r) {
      final path = r.requestedUri.path;

      if (LetsEncrypt.isSelfCheckPath(path)) {
        if (LetsEncrypt.isACMEPath(path)) {
          return processACMEChallengeRequest(r);
        } else if (LetsEncrypt.isSelfCheckPath(path)) {
          return processSelfCheckRequest(r);
        }
      }

      return handler(r);
    }

    var server = await serve(handlerWithChallenge, bindingAddress, port,
        backlog: backlog, shared: shared);

    Future<HttpServer> startSecureServer(SecurityContext securityContext) {
      return serve(handlerWithChallenge, bindingAddress, securePort,
          securityContext: securityContext, backlog: backlog, shared: shared);
    }

    HttpServer? secureServer;

    var domains = domainsAndEmails.keys.toList();

    _logMsg('$certificatesHandler');
    _logMsg('Handled domains: ${certificatesHandler.listAllHandledDomains()}');

    var securityContext = await certificatesHandler.buildSecurityContext(
        domains,
        loadAllHandledDomains: loadAllHandledDomains);

    _logMsg(
        'securityContext[loadAllHandledDomains: $loadAllHandledDomains]: $securityContext');

    if (securityContext == null) {
      if (!requestCertificate) {
        throw StateError(
            "No previous SecureContext! Can't request certificate");
      }

      var domainsToCheck = certificatesHandler.listNotHandledDomains(domains);

      _logMsg('Requesting certificate for: $domainsToCheck');

      for (var domain in domainsToCheck) {
        var domainEmail = domainsAndEmails[domain]!;
        var ok = await this.requestCertificate(domain, domainEmail);
        if (!ok) {
          throw StateError("Error requesting certificate!");
        }
      }

      securityContext = await certificatesHandler.buildSecurityContext(domains,
          loadAllHandledDomains: loadAllHandledDomains);
      if (securityContext == null) {
        throw StateError(
            "Error loading SecureContext after successful request of certificate for: $domains");
      }

      _logMsg('Starting secure server> port: $securePort ; domains: $domains');
      secureServer = await startSecureServer(securityContext);
    } else {
      secureServer = await startSecureServer(securityContext);

      if (checkCertificate) {
        _logMsg('Checking certificate for: $domains');

        var refreshedCertificate = false;

        for (var domain in domains) {
          var domainEmail = domainsAndEmails[domain]!;

          var checkCertificateStatus = await this.checkCertificate(
              domain, domainEmail,
              requestCertificate: requestCertificate,
              forceRequestCertificate: forceRequestCertificate);

          _logMsg('CheckCertificateStatus: $checkCertificateStatus');

          if (checkCertificateStatus.isOkRefreshed) {
            refreshedCertificate = true;
          } else if (checkCertificateStatus.isNotOK) {
            throw StateError(
                "Certificate check error! Status: $checkCertificateStatus ; domain: $domain");
          }
        }

        if (refreshedCertificate) {
          _logMsg('Refreshing SecureContext due new certificate.');
          securityContext = await certificatesHandler.buildSecurityContext(
              domains,
              loadAllHandledDomains: loadAllHandledDomains);
          if (securityContext == null) {
            throw StateError(
                "Error loading SecureContext after successful certificate check for: $domains");
          }

          _logMsg('Restarting secure server...');
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
    var domainHttpsOK = await isDomainHttpsOK(domain,
        maxRetries: maxRetries, retryInterval: retryInterval);
    if (domainHttpsOK && !forceRequestCertificate) {
      return CheckCertificateStatus.ok;
    }

    if (!requestCertificate) {
      return CheckCertificateStatus.invalid;
    }

    try {
      var ok = await this.requestCertificate(domain, email);
      return ok
          ? CheckCertificateStatus.okRefreshed
          : CheckCertificateStatus.error;
    } catch (e) {
      _logMsg(e);
      return CheckCertificateStatus.error;
    }
  }

  /// Request a certificate for [domain] using an `ACME` client.
  ///
  /// Calls [doACMEChallenge].
  Future<bool> requestCertificate(String domain, String email) async {
    var accountKeyPair = await certificatesHandler.ensureAccountPEMKeyPair();

    await certificatesHandler.ensureDomainPEMKeyPair(domain);

    var csr = await certificatesHandler.generateCSR(domain, email);
    if (csr == null) {
      throw StateError("Can't generate CSR for domain: $domain");
    }

    var certs = await doACMEChallenge(domain, [email],
        accountKeyPair.privateKeyPEM, accountKeyPair.publicKeyPEM, csr);

    var ok =
        await certificatesHandler.saveSignedCertificateChain(domain, certs);

    return ok;
  }

  /// Returns true if [domain] HTTPS is OK.
  Future<bool> isDomainHttpsOK(String domain,
      {int maxRetries = 3, Duration? retryInterval}) async {
    if (retryInterval == null) {
      retryInterval ??= Duration(seconds: 1);
    } else if (retryInterval.inMilliseconds < 10) {
      retryInterval = Duration(milliseconds: 10);
    }

    var domainURL =
        Uri.parse('https://$domain/.well-known/check/${DateTime.now()}');

    for (var i = 0; i < maxRetries; ++i) {
      if (i > 0) {
        await Future.delayed(retryInterval);
      }
      var ok = await isUrlOK(domainURL);
      if (ok) return true;
    }

    return false;
  }

  /// Returns `true` if the [url] is OK (performs a request).
  Future<bool> isUrlOK(Uri url) async {
    try {
      var body = await getURL(url);
      return body != null;
    } catch (_) {
      return false;
    }
  }

  /// Performs a HTTP request for [url]. Returns a [String] with the body if OK.
  Future<String?> getURL(Uri url) async {
    HttpClient client = HttpClient()
      ..badCertificateCallback = badCertificateCallback;

    var request = await client.getUrl(url);
    var response = await request.close();

    var ok = response.statusCode == 200;
    if (!ok) return null;

    var data = await response.transform(Utf8Decoder()).toList();
    var body = data.join();

    return body;
  }

  /// Handles a bad certificate triggered by [HttpClient].
  /// Should return `true` to accept a bad certificate (like a self-signed).
  ///
  /// Defaults to ![production], since in [production] the staging certificate
  /// is invalid.
  bool badCertificateCallback(X509Certificate cert, String host, int port) {
    return !production;
  }
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
