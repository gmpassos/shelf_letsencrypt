import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:basic_utils/basic_utils.dart' hide Domain;
import 'package:collection/collection.dart';

import '../shelf_letsencrypt.dart';

/// Base class for a certificate handler.
///
/// Used by [LetsEncrypt].
abstract class CertificatesHandler {
  CertificatesHandler(
      {this.accountDirectory = defaultAccountDirectoryName,
      this.privateKeyPEMFileName = defaultPrivateKeyPEMFileName,
      this.publicKeyPEMFileName = defaultPublicKeyPEMFileName,
      this.fullChainPEMFileName = defaultFullChainPEMFileName});
  static const String defaultAccountDirectoryName = 'account';

  static const String defaultPrivateKeyPEMFileName = 'privkey.pem';

  static const String defaultPublicKeyPEMFileName = 'pubkey.pem';

  static const String defaultFullChainPEMFileName = 'fullchain.pem';

  /// The account directory.
  final String accountDirectory;

  /// The file name of a private key PEM file.
  final String privateKeyPEMFileName;

  /// The file name of a public key PEM file.
  final String publicKeyPEMFileName;

  /// The file name of a full-chain PEM file.
  final String fullChainPEMFileName;

  /// Builds a SecurityContext for [domains] that can be used in a
  /// secure [HttpServer] and [LetsEncrypt].
  ///
  /// If this instance doesn't have a valid certificate
  /// for [domains] it will return `null`.
  ///
  /// See [LetsEncrypt.startServer].
  FutureOr<SecurityContext?> buildSecurityContext(List<Domain> domains,
      {bool loadAllHandledDomains = true});

  /// Returns a [List] of all the handled domains.
  List<String> listAllHandledDomains({bool checkSecurityContext = true});

  /// Returns `true` if [domain] certificate is already handled.
  bool isHandledDomainCertificate(String domain,
      {bool checkSecurityContext = true});

  /// Returns a [List] of handled [domains].
  List<String> listHandledDomains(List<String> domains,
          {bool checkSecurityContext = true}) =>
      domains
          .where((d) => isHandledDomainCertificate(d,
              checkSecurityContext: checkSecurityContext))
          .toList();

  /// Returns a [List] of NOT handled [domains].
  List<Domain> listNotHandledDomains(List<Domain> domains,
          {bool checkSecurityContext = true}) =>
      domains
          .where((d) => !isHandledDomainCertificate(d.name,
              checkSecurityContext: checkSecurityContext))
          .toList();

  bool isCertificateExpired(String certificatePEM) {
    try {
      final pemList = splitPEMs(certificatePEM);

      final certificate = X509Utils.x509CertificateFromPem(pemList.first);

      final tbsCertificateValidity = certificate.tbsCertificate?.validity;
      if (tbsCertificateValidity == null) {
        return false;
      }

      final notBefore = tbsCertificateValidity.notBefore;
      final notAfter = tbsCertificateValidity.notAfter;

      final now = DateTime.now();

      if (now.compareTo(notBefore) < 0) {
        return true;
      }
      if (now.compareTo(notAfter) > 0) {
        return true;
      }

      return false;
      // ignore: avoid_catches_without_on_clauses
    } catch (_) {
      return true;
    }
  }

  /// Ensures that an account key pair exists.
  Future<PEMKeyPair> ensureAccountPEMKeyPair() async {
    var keyPair = await getAccountPEMKeyPair();
    keyPair ??= await generateAccountPEMKeyPair();

    if (keyPair == null) {
      throw StateError("Can't generate account key pair.");
    }

    return keyPair;
  }

  /// Ensures that a key pair for [cn] exists.
  Future<PEMKeyPair> ensureDomainPEMKeyPair(String cn) async {
    var keyPair = await getDomainPEMKeyPair(cn);
    keyPair ??= await generateDomainPEMKeyPair(cn);

    if (keyPair == null) {
      throw StateError("Can't generate domain key pair: $cn");
    }

    return keyPair;
  }

  /// Returns the account key pair.
  Future<PEMKeyPair?> getAccountPEMKeyPair() async {
    final privateKeyPEM = loadAccountPrivateKeyPEM();
    final publicKeyPEM = loadAccountPublicKeyPEM();

    final privateKeyPEMData = await privateKeyPEM;
    final publicKeyPEMData = await publicKeyPEM;

    if (privateKeyPEMData == null || publicKeyPEMData == null) {
      return null;
    }

    final pair = PEMKeyPair(privateKeyPEMData, publicKeyPEMData);
    return pair;
  }

  /// Returns the key pair for the common name [cn].
  Future<PEMKeyPair?> getDomainPEMKeyPair(String cn) async {
    final privateKeyPEM = loadDomainPrivateKeyPEM(cn);
    final publicKeyPEM = loadDomainPublicKeyPEM(cn);

    final privateKeyPEMData = await privateKeyPEM;
    final publicKeyPEMData = await publicKeyPEM;

    if (privateKeyPEMData == null || publicKeyPEMData == null) {
      return null;
    }

    final pair = PEMKeyPair(privateKeyPEMData, publicKeyPEMData);
    return pair;
  }

  /// Loads the current account private key PEM.
  FutureOr<String?> loadAccountPrivateKeyPEM();

  /// Loads the current account public key PEM.
  FutureOr<String?> loadAccountPublicKeyPEM();

  /// Generates and stores the account key pair.
  ///
  /// - If [force] is `true` overwrites any current key pair.
  Future<PEMKeyPair?> generateAccountPEMKeyPair({bool force = false});

  /// Loads the private key of [cn] in PEM format.
  FutureOr<String?> loadDomainPrivateKeyPEM(String cn);

  /// Loads the public key of [cn] in PEM format.
  FutureOr<String?> loadDomainPublicKeyPEM(String cn);

  /// Generates a key pair in PEM format.
  PEMKeyPair generatePEMKeyPair();

  /// Generates and stores a key pair for [cn] in PEM format.
  ///
  /// - If [force] is `true` overwrites any current key pair.
  Future<PEMKeyPair?> generateDomainPEMKeyPair(String cn, {bool force = false});

  /// Generates a `CSR` (Certificate Signing Request) for [cn].
  Future<String?> generateCSR(String cn, String email,
      {String? organizationName,
      String? organizationUnit,
      String? locality,
      String? state,
      String? country});

  /// Saves a signed certificate chain for [cn].
  ///
  /// This is used by [buildSecurityContext] to construct
  /// a [SecurityContext] for a secure [HttpServer].
  Future<bool> saveSignedCertificateChain(
      String cn, List<String> signedCertificatesChain);

  static String fixPEM(String pem) {
    pem = pem.replaceAllMapped(RegExp(r'\s*(--+BEGIN[^-\n\r]+--+)\s*'), (m) {
      final s = m.group(1);
      return '\n$s\n';
    });

    pem = pem.replaceAllMapped(RegExp(r'\s*(--+END[^-\n\r]+--+)\s*'), (m) {
      final s = m.group(1);
      return '\n$s\n';
    });

    pem = '${pem.trim()}\n';

    return pem;
  }

  /// Splits the PEM entries in [pemList].
  static List<String> splitPEMs(String pemList) {
    pemList = pemList.trim();

    final allPEMs = <String>[];

    final result =
        pemList.splitMapJoin(RegExp(r'(--+BEGIN[^-\n\r]+--+)'), onMatch: (m) {
      final s = m.group(1)!;
      allPEMs.add(s);
      return '<';
    }, onNonMatch: (s) {
      if (s.trim().isEmpty) {
        return '';
      }
      if (allPEMs.isNotEmpty) {
        final pem = allPEMs.removeLast() + s;
        allPEMs.add(pem);
      }
      return '>';
    });

    assert(result.replaceAll('<>', '').isEmpty, 'result should be empty');

    return allPEMs.map(fixPEM).toList();
  }

  /// Joins [pemList] in a single [String].
  ///
  /// Also fixes PEM format ([CertificatesHandler.fixPEM]).
  static String joinPEMs(List<String> pemList) {
    pemList = pemList.map(CertificatesHandler.fixPEM).toList();

    final fullChainPEM =
        '${pemList.join('\n\n').replaceAll(RegExp('\n\n+'), '\n\n').trim()}\n';

    return fullChainPEM;
  }
}

/// Holds [domains] certificates to load into a [SecurityContext].
abstract class DomainCertificate {
  DomainCertificate(Iterable<String> domains) {
    final domainsList = domains.toList().toSet().toList()..sort();
    this.domains = domainsList;
  }

  /// The domains of the certificates.
  late final List<String> domains;

  /// The full-chain certificates in PEM format.
  String get fullChainPEM;

  /// The private key certificates in PEM format.
  String get privateKeyPEM;

  /// Merge this instance with [other].
  DomainCertificate merge(DomainCertificate other) {
    final fullChain = '$fullChainPEM\n\n${other.fullChainPEM}';
    final privateKey = '$privateKeyPEM\n\n${other.privateKeyPEM}';

    return DomainCertificatePEM(
        [...domains, ...other.domains], fullChain, privateKey);
  }

  /// Defines this certificates into [securityContext].
  void define(SecurityContext securityContext);

  static const ListEquality<String> _listEqualityString =
      ListEquality<String>();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DomainCertificate &&
          _listEqualityString.equals(domains, other.domains);

  @override
  int get hashCode => _listEqualityString.hash(domains);

  @override
  String toString() => 'DomainCertificate{domains: $domains}';
}

/// A [DomainCertificate] implementation using PEM content.
class DomainCertificatePEM extends DomainCertificate {
  DomainCertificatePEM(
      List<String> super.domains, this.fullChainPEM, this.privateKeyPEM);
  @override
  final String fullChainPEM;

  @override
  final String privateKeyPEM;

  @override
  void define(SecurityContext securityContext) {
    securityContext
      ..useCertificateChainBytes(utf8.encode(fullChainPEM))
      ..usePrivateKeyBytes(utf8.encode(privateKeyPEM));
  }
}
