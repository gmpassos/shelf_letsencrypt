import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:basic_utils/basic_utils.dart';
import 'package:collection/collection.dart';
import 'package:path/path.dart' as pack_path;

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
  /// See [LetsEncrypt.startSecureServer].
  FutureOr<SecurityContext?> buildSecurityContext(List<String> domains,
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
  List<String> listNotHandledDomains(List<String> domains,
          {bool checkSecurityContext = true}) =>
      domains
          .where((d) => !isHandledDomainCertificate(d,
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

/// A [SecurityContext] builder.
class SecurityContextBuilder {
  static bool defineMerged = false;

  final Set<DomainCertificate> domainsCertificates = <DomainCertificate>{};

  SecurityContext build() {
    final securityContext = SecurityContext();

    if (defineMerged) {
      domainsCertificates
          .reduce((value, element) => value.merge(element))
          .define(securityContext);
    } else {
      for (final d in domainsCertificates) {
        d.define(securityContext);
      }
    }

    return securityContext;
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

/// A [DomainCertificate] implementation using file paths.
class DomainCertificateFilePath extends DomainCertificate {
  DomainCertificateFilePath(List<String> super.domains, this.fullChainFilePath,
      this.privateKeyFilePath);
  final String fullChainFilePath;

  final String privateKeyFilePath;

  @override
  String get fullChainPEM => File(fullChainFilePath).readAsStringSync();

  @override
  String get privateKeyPEM => File(privateKeyFilePath).readAsStringSync();

  @override
  void define(SecurityContext securityContext) {
    securityContext
      ..useCertificateChain(fullChainFilePath)
      ..usePrivateKey(privateKeyFilePath);
  }
}

/// A [CertificatesHandler] implementation using [dart:io].
class CertificatesHandlerIO extends CertificatesHandler {
  CertificatesHandlerIO(this.directory,
      {super.accountDirectory,
      super.privateKeyPEMFileName,
      super.publicKeyPEMFileName,
      super.fullChainPEMFileName}) {
    directory.createSync(recursive: true);
  }

  /// The [Directory] to storage certificates.
  final Directory directory;

  @override
  List<String> listAllHandledDomains({bool checkSecurityContext = true}) {
    final domainsDirs = directory
        .listSync()
        .where(_isDomainDirectory)
        .map((e) => _pathFileName(e.path))
        .where((e) => isHandledDomainCertificate(e,
            checkSecurityContext: checkSecurityContext))
        .toList();

    return domainsDirs;
  }

  bool _isDomainDirectory(FileSystemEntity e) {
    if (e.statSync().type != FileSystemEntityType.directory) {
      return false;
    }

    final dirName = _pathFileName(e.path);

    if (dirName == accountDirectory || dirName.startsWith('.')) {
      return false;
    }

    final dir = Directory(e.path);

    final files = dir.listSync(followLinks: false);
    final pemFiles = files.where((f) => f.path.endsWith('pem')).toList();

    if (pemFiles.isEmpty) {
      return false;
    }

    final fullChainFile =
        pemFiles.firstWhereOrNull((f) => f.path.endsWith(fullChainPEMFileName));

    if (fullChainFile == null) {
      return false;
    }

    final privateKeyFile = pemFiles
        .firstWhereOrNull((f) => f.path.endsWith(privateKeyPEMFileName));

    if (privateKeyFile == null) {
      return false;
    }

    return true;
  }

  String _pathFileName(String path) => pack_path.split(path).last;

  @override
  Future<SecurityContext?> buildSecurityContext(List<String> domains,
      {bool loadAllHandledDomains = true}) async {
    final securityContextBuilder = SecurityContextBuilder();

    for (final domain in domains) {
      final domainOk =
          await _useDomainCertificate(securityContextBuilder, domain);
      if (!domainOk) {
        return null;
      }
    }

    if (loadAllHandledDomains) {
      final handledDomains = listAllHandledDomains();

      for (final d in handledDomains) {
        if (!domains.contains(d)) {
          await _useDomainCertificate(securityContextBuilder, d);
        }
      }
    }

    final securityContext = securityContextBuilder.build();
    return securityContext;
  }

  Future<bool> _useDomainCertificate(
      SecurityContextBuilder securityContextBuilder, String domain) async {
    final fullChainFile = fileDomainFullChainPEM(domain);
    final privateKeyFile = fileDomainPrivateKeyPEM(domain);

    if (!_fileExistsWithContent(fullChainFile) ||
        !_fileExistsWithContent(privateKeyFile)) {
      return false;
    }

    final fullChainPath = fullChainFile.path;
    final privateKeyPath = privateKeyFile.path;

    securityContextBuilder.domainsCertificates.add(
        DomainCertificateFilePath([domain], fullChainPath, privateKeyPath));

    return true;
  }

  @override
  bool isHandledDomainCertificate(String domain,
      {bool checkSecurityContext = true}) {
    final fullChainFile = fileDomainFullChainPEM(domain);
    final privateKeyFile = fileDomainPrivateKeyPEM(domain);

    if (!_fileExistsWithContent(fullChainFile) ||
        !_fileExistsWithContent(privateKeyFile)) {
      return false;
    }

    final certificateExpired =
        isCertificateExpired(fullChainFile.readAsStringSync());
    if (certificateExpired) {
      return false;
    }

    if (!checkSecurityContext) {
      return true;
    }

    try {
      final fullChainPath = fullChainFile.path;
      final privateKeyPath = privateKeyFile.path;

      SecurityContext()
        ..useCertificateChain(fullChainPath)
        ..usePrivateKey(privateKeyPath);

      return true;
    // ignore: avoid_catches_without_on_clauses
    } catch (_) {
      return false;
    }
  }

  File fileAccountPrivateKeyPEM() => File(
      pack_path.join(directory.path, accountDirectory, privateKeyPEMFileName));

  File fileAccountPublicKeyPEM() => File(
      pack_path.join(directory.path, accountDirectory, publicKeyPEMFileName));

  File fileDomainPrivateKeyPEM(String cn) =>
      File(pack_path.join(directory.path, cn, privateKeyPEMFileName));

  File fileDomainPublicKeyPEM(String cn) =>
      File(pack_path.join(directory.path, cn, publicKeyPEMFileName));

  File fileDomainFullChainPEM(String cn) =>
      File(pack_path.join(directory.path, cn, fullChainPEMFileName));

  @override
  FutureOr<String?> loadAccountPrivateKeyPEM() {
    final file = fileAccountPrivateKeyPEM();
    return _readFileWithContent(file);
  }

  @override
  FutureOr<String?> loadAccountPublicKeyPEM() {
    final file = fileAccountPublicKeyPEM();
    return _readFileWithContent(file);
  }

  @override
  FutureOr<String?> loadDomainPrivateKeyPEM(String cn) {
    final file = fileDomainPrivateKeyPEM(cn);
    return _readFileWithContent(file);
  }

  @override
  FutureOr<String?> loadDomainPublicKeyPEM(String cn) {
    final file = fileDomainPublicKeyPEM(cn);
    return _readFileWithContent(file);
  }

  String? _readFileWithContent(File file) {
    if (_fileExistsWithContent(file)) {
      return file.readAsStringSync();
    }
    return null;
  }

  bool _fileExistsWithContent(File file) =>
      file.existsSync() && file.lengthSync() > 1;

  @override
  Future<PEMKeyPair?> generateAccountPEMKeyPair({bool force = false}) async {
    final filePrivateKey = fileAccountPrivateKeyPEM();
    final filePublicKey = fileAccountPublicKeyPEM();

    return _generateStoredKeyPair(filePrivateKey, filePublicKey, force);
  }

  @override
  Future<PEMKeyPair?> generateDomainPEMKeyPair(String cn,
      {bool force = false}) async {
    final filePrivateKey = fileDomainPrivateKeyPEM(cn);
    final filePublicKey = fileDomainPublicKeyPEM(cn);

    return _generateStoredKeyPair(filePrivateKey, filePublicKey, force);
  }

  Future<PEMKeyPair?> _generateStoredKeyPair(
      File filePrivateKey, File filePublicKey, bool force) async {
    if (!force &&
        (_fileExistsWithContent(filePrivateKey) ||
            _fileExistsWithContent(filePublicKey))) {
      return getAccountPEMKeyPair();
    }

    final keyPair = generatePEMKeyPair();

    filePrivateKey.parent.createSync(recursive: true);
    filePublicKey.parent.createSync(recursive: true);

    filePrivateKey.writeAsStringSync(keyPair.privateKeyPEM);
    filePublicKey.writeAsStringSync(keyPair.publicKeyPEM);

    return keyPair;
  }

  @override
  PEMKeyPair generatePEMKeyPair() {
    final rsaKeyPair = CryptoUtils.generateRSAKeyPair();

    final rsaPrivateKey = rsaKeyPair.privateKey as RSAPrivateKey;
    final rsaPublicKey = rsaKeyPair.publicKey as RSAPublicKey;

    final privateKeyPEM = CryptoUtils.encodeRSAPrivateKeyToPem(rsaPrivateKey);
    final publicKeyPEM = CryptoUtils.encodeRSAPublicKeyToPem(rsaPublicKey);

    final keyPair =
        PEMKeyPair(privateKeyPEM, publicKeyPEM, rsaPrivateKey, rsaPublicKey);
    return keyPair;
  }

  @override
  Future<String?> generateCSR(String cn, String email,
      {String? organizationName,
      String? organizationUnit,
      String? locality,
      String? state,
      String? country}) async {
    final domainKeyPair = await getDomainPEMKeyPair(cn);
    if (domainKeyPair == null) {
      return null;
    }

    final attributes = {
      'CN': cn,
      if (organizationName != null) 'O': organizationName,
      if (organizationUnit != null) 'OU': organizationUnit,
      if (locality != null) 'L': locality,
      if (state != null) 'ST': state,
      if (country != null) 'C': country,
    };

    final csr = X509Utils.generateRsaCsrPem(
        attributes, domainKeyPair.privateKey, domainKeyPair.publicKey);

    return csr;
  }

  @override
  Future<bool> saveSignedCertificateChain(
      String cn, List<String> signedCertificatesChain) async {
    final fullChainPEM = CertificatesHandler.joinPEMs(signedCertificatesChain);

    final filePrivateKey = fileDomainFullChainPEM(cn);

    filePrivateKey.parent.createSync(recursive: true);
    filePrivateKey.writeAsStringSync(fullChainPEM);

    return true;
  }

  @override
  String toString() => 'CertificatesHandlerIO@$directory';
}

class PEMKeyPair {
  PEMKeyPair(this.privateKeyPEM, this.publicKeyPEM,
      [this._privateKey, this._publicKey]);
  final String privateKeyPEM;
  final String publicKeyPEM;

  RSAPrivateKey? _privateKey;

  RSAPrivateKey get privateKey =>
      _privateKey ??= CryptoUtils.rsaPrivateKeyFromPem(privateKeyPEM);

  RSAPublicKey? _publicKey;

  RSAPublicKey get publicKey =>
      _publicKey ??= CryptoUtils.rsaPublicKeyFromPem(publicKeyPEM);
}
