import 'dart:convert';
import 'dart:io';

import 'package:basic_utils/basic_utils.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';

/// A minimal in-process ACME server (RFC 8555) with the subset of the protocol
/// used by `package:acme_client`.
///
/// It does not verify JWS signatures, but it rejects replayed nonces like Let's
/// Encrypt (`badNonce`), and it performs a real HTTP-01
/// validation: it fetches the challenge from [challengePort] (on loopback, see
/// `LoopbackHttpOverrides`) and only issues a certificate when the key
/// authorization matches.
class FakeAcmeServer {
  FakeAcmeServer({required this.challengePort});

  /// The HTTP port of the server answering the HTTP-01 challenges.
  final int challengePort;

  /// `newAccount` fails with `400` (the account can't be created or found).
  bool rejectAccounts = false;

  /// The number of next `newAccount` requests answered without a
  /// `Replay-Nonce`, which makes `AcmeClient` throw.
  int brokenAccountRequests = 0;

  /// `newOrder` fails with `403`.
  bool rejectNewOrder = false;

  /// Orders have no authorizations.
  bool emptyAuthorizations = false;

  /// Orders stay `pending` after a valid challenge.
  bool orderNotReady = false;

  /// Finalization returns an `invalid` order.
  bool rejectFinalize = false;

  /// The certificate download fails with `500`.
  bool rejectCertificate = false;

  /// The certificate download returns a PEM block that is not a certificate.
  bool corruptCertificate = false;

  /// The number of certificates issued.
  int certificatesIssued = 0;

  late HttpServer _server;
  final _accounts = <String>{};
  final _orders = <_Order>[];
  final _caKeyPair = CryptoUtils.generateRSAKeyPair();
  var _nonce = 0;
  final _unusedNonces = <String>{};

  /// The server URL. It still points to the closed port after [close].
  late String baseUrl;

  Future<void> start() async {
    _server = await serve(_handle, InternetAddress.loopbackIPv4, 0);
    baseUrl = 'http://127.0.0.1:${_server.port}';
  }

  Future<void> close() => _server.close(force: true);

  Future<Response> _handle(Request request) async {
    final segments = request.url.pathSegments;
    final name = segments.isEmpty ? '' : segments.first;
    final id = segments.length > 1 ? int.parse(segments[1]) : -1;

    if (request.method == 'GET' && name == 'directory') {
      return _json({
        'newNonce': '$baseUrl/nonce',
        'newAccount': '$baseUrl/account',
        'newOrder': '$baseUrl/new-order',
        'revokeCert': '$baseUrl/revoke',
        'keyChange': '$baseUrl/key-change',
      });
    }
    if (request.method == 'HEAD' && name == 'nonce') {
      return Response.ok(null, headers: _nonceHeader());
    }
    if (request.method != 'POST') return Response.notFound(null);

    final jws = _Jws.parse(await request.readAsString());
    // Like Let's Encrypt, accept each issued nonce only once.
    if (!_unusedNonces.remove(jws.protected['nonce'])) {
      return _error(400, 'badNonce');
    }
    switch (name) {
      case 'account':
        return _account(jws);
      case 'new-order':
        return _newOrder(jws);
      case 'order':
        return _json(_orders[id].toJson(this));
      case 'authz':
        return _json(_orders[id].authorizationJson(this));
      case 'chall':
        return _challenge(_orders[id], jws);
      case 'finalize':
        return _finalize(_orders[id], jws);
      case 'cert':
        return _certificate(_orders[id]);
    }
    return Response.notFound(null);
  }

  Response _account(_Jws jws) {
    if (brokenAccountRequests > 0) {
      brokenAccountRequests--;
      return Response.ok('{"status":"valid"}',
          headers: {'Content-Type': 'application/json'});
    }

    final key = jws.protected['jwk']?['n'] as String?;
    final known = key != null && _accounts.contains(key);
    if (rejectAccounts || key == null) {
      return _error(400, 'accountDoesNotExist');
    }
    if (!known && jws.payload['onlyReturnExisting'] == true) {
      return _error(400, 'accountDoesNotExist');
    }
    _accounts.add(key);
    return _json({'status': 'valid', 'contact': jws.payload['contact']},
        status: known ? 200 : 201,
        location: '$baseUrl/account/${_accounts.toList().indexOf(key)}');
  }

  Response _newOrder(_Jws jws) {
    if (rejectNewOrder) return _error(403, 'unauthorized');

    final identifiers = jws.payload['identifiers'] as List;
    final domain = (identifiers.first as Map)['value'] as String;
    final order = _Order(_orders.length, domain);
    _orders.add(order);
    return _json(order.toJson(this),
        status: 201, location: '$baseUrl/order/${order.id}');
  }

  Future<Response> _challenge(_Order order, _Jws jws) async {
    final expected = jws.payload['keyAuthorization'] as String;
    final served = await _fetchChallenge(order);
    order.status = served == expected ? 'ready' : 'invalid';
    return _json(order.challengeJson(this));
  }

  Future<String?> _fetchChallenge(_Order order) async {
    final client = HttpClient();
    try {
      final request = await client.getUrl(Uri.parse('http://${order.domain}:'
          '$challengePort/.well-known/acme-challenge/${order.token}'));
      final response = await request.close();
      final body = await response.transform(utf8.decoder).join();
      return response.statusCode == 200 ? body.trim() : null;
    } on IOException {
      return null;
    } finally {
      client.close(force: true);
    }
  }

  Response _finalize(_Order order, _Jws jws) {
    if (rejectFinalize || order.status != 'ready') {
      order.status = 'invalid';
      return _json(order.toJson(this));
    }

    final csrDer = base64Url.decode(base64Url.normalize(jws.payload['csr']));
    final csrPem = X509Utils.formatKeyString(
        base64.encode(csrDer), X509Utils.BEGIN_CSR, X509Utils.END_CSR);
    order.certificatePem = X509Utils.generateSelfSignedCertificate(
        _caKeyPair.privateKey, csrPem, 90,
        sans: [order.domain],
        issuer: {'CN': 'Fake ACME CA'},
        serialNumber: '${order.id + 1}');
    order.status = 'valid';
    certificatesIssued++;
    return _json(order.toJson(this));
  }

  Response _certificate(_Order order) {
    if (rejectCertificate) return _error(500, 'serverInternal');
    final pem = corruptCertificate
        ? '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'
        : order.certificatePem;
    return Response.ok(pem, headers: {
      ..._nonceHeader(),
      'Content-Type': 'application/pem-certificate-chain',
    });
  }

  Map<String, String> _nonceHeader() {
    final nonce = 'nonce-${_nonce++}';
    _unusedNonces.add(nonce);
    return {'Replay-Nonce': nonce};
  }

  Response _json(Object body, {int status = 200, String? location}) =>
      Response(status, body: json.encode(body), headers: {
        ..._nonceHeader(),
        'Content-Type': 'application/json',
        if (location != null) 'Location': location,
      });

  Response _error(int status, String type) => Response(status,
          body: json.encode({'type': 'urn:ietf:params:acme:error:$type'}),
          headers: {
            ..._nonceHeader(),
            'Content-Type': 'application/problem+json',
          });
}

class _Order {
  _Order(this.id, this.domain);

  final int id;
  final String domain;
  final String token = 'token-${DateTime.now().microsecondsSinceEpoch}';
  String status = 'pending';
  String? certificatePem;

  Map<String, Object?> toJson(FakeAcmeServer server) => {
        'status':
            server.orderNotReady && status == 'ready' ? 'pending' : status,
        'identifiers': [
          {'type': 'dns', 'value': domain}
        ],
        'authorizations': [
          if (!server.emptyAuthorizations) '${server.baseUrl}/authz/$id'
        ],
        'finalize': '${server.baseUrl}/finalize/$id',
        if (status == 'valid') 'certificate': '${server.baseUrl}/cert/$id',
      };

  /// The authorization and challenge status for the order [status].
  String get _authorizationStatus => switch (status) {
        'pending' || 'invalid' => status,
        _ => 'valid',
      };

  Map<String, Object?> authorizationJson(FakeAcmeServer server) => {
        'identifier': {'type': 'dns', 'value': domain},
        'status': _authorizationStatus,
        'challenges': [challengeJson(server)],
      };

  Map<String, Object?> challengeJson(FakeAcmeServer server) => {
        'type': 'http-01',
        'url': '${server.baseUrl}/chall/$id',
        'token': token,
        'status': _authorizationStatus,
      };
}

/// A flattened JWS (RFC 7515), as sent by `acme_client`.
class _Jws {
  _Jws(this.protected, this.payload);

  factory _Jws.parse(String body) {
    final jws = json.decode(body) as Map<String, dynamic>;
    final protected = jws['protected'] ??
        ((jws['signatures'] as List).first as Map)['protected'];
    final payload = _decode(jws['payload'] as String);
    return _Jws(
        json.decode(_decode(protected as String)) as Map<String, dynamic>,
        payload.isEmpty
            ? const {}
            : json.decode(payload) as Map<String, dynamic>);
  }

  final Map<String, dynamic> protected;
  final Map<String, dynamic> payload;

  static String _decode(String value) =>
      utf8.decode(base64Url.decode(base64Url.normalize(value)));
}
