import 'dart:async';
import 'dart:io';

import 'package:basic_utils/basic_utils.dart';
import 'package:path/path.dart' as pack_path;
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

/// Base class for a certificate handler.
///
/// Used by [LetsEncrypt].
abstract class CertificatesHandler {
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

  CertificatesHandler(
      {this.accountDirectory = defaultAccountDirectoryName,
      this.privateKeyPEMFileName = defaultPrivateKeyPEMFileName,
      this.publicKeyPEMFileName = defaultPublicKeyPEMFileName,
      this.fullChainPEMFileName = defaultFullChainPEMFileName});

  /// Builds a SecurityContext for [domain] that can be used in a secure [HttpServer] and [LetsEncrypt].
  ///
  /// If this instance doesn't have a valid certificate for [domain] it will return `null`.
  ///
  /// See [LetsEncrypt.startSecureServer].
  FutureOr<SecurityContext?> buildSecurityContext(String domain);

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
    var privateKeyPEM = loadAccountPrivateKeyPEM();
    var publicKeyPEM = loadAccountPublicKeyPEM();

    var privateKeyPEMData = await privateKeyPEM;
    var publicKeyPEMData = await publicKeyPEM;

    if (privateKeyPEMData == null || publicKeyPEMData == null) {
      return null;
    }

    var pair = PEMKeyPair(privateKeyPEMData, publicKeyPEMData);
    return pair;
  }

  /// Returns the key pair for [domain].
  Future<PEMKeyPair?> getDomainPEMKeyPair(String cn) async {
    var privateKeyPEM = loadDomainPrivateKeyPEM(cn);
    var publicKeyPEM = loadDomainPublicKeyPEM(cn);

    var privateKeyPEMData = await privateKeyPEM;
    var publicKeyPEMData = await publicKeyPEM;

    if (privateKeyPEMData == null || publicKeyPEMData == null) {
      return null;
    }

    var pair = PEMKeyPair(privateKeyPEMData, publicKeyPEMData);
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
  /// This is used by [buildSecurityContext] to construct a [SecurityContext] for
  /// a secure [HttpServer].
  Future<bool> saveSignedCertificateChain(
      String cn, List<String> signedCertificatesChain);

  static String fixPEM(String pem) {
    pem = pem.replaceAllMapped(RegExp(r'\s*(--+BEGIN[^-\n\r]+--+)\s*'), (m) {
      var s = m.group(1);
      return '\n$s\n';
    });

    pem = pem.replaceAllMapped(RegExp(r'\s*(--+END[^-\n\r]+--+)\s*'), (m) {
      var s = m.group(1);
      return '\n$s\n';
    });

    pem = pem.trim() + '\n';

    return pem;
  }

  /// Splits the PEM entries in [pemList].
  static List<String> splitPEMs(String pemList) {
    pemList = pemList.trim();

    var allPEMs = <String>[];

    var result =
        pemList.splitMapJoin(RegExp(r'(--+BEGIN[^-\n\r]+--+)'), onMatch: (m) {
      var s = m.group(1)!;
      allPEMs.add(s);
      return '<';
    }, onNonMatch: (s) {
      if (s.trim().isEmpty) {
        return '';
      }
      if (allPEMs.isNotEmpty) {
        var pem = allPEMs.removeLast() + s;
        allPEMs.add(pem);
      }
      return '>';
    });

    assert(result.replaceAll('<>', '').isEmpty);

    allPEMs = allPEMs.map(fixPEM).toList();

    return allPEMs;
  }

  /// Joins [pemList] in a single [String].
  ///
  /// Also fixes PEM format ([CertificatesHandler.fixPEM]).
  static String joinPEMs(List<String> pemList) {
    pemList = pemList.map(CertificatesHandler.fixPEM).toList();

    var fullChainPEM =
        pemList.join('\n\n').replaceAll(RegExp('\n\n+'), '\n\n').trim() + '\n';

    return fullChainPEM;
  }
}

class CertificatesHandlerIO extends CertificatesHandler {
  /// The [Directory] to storage certificates.
  final Directory directory;

  CertificatesHandlerIO(this.directory,
      {String accountDirectory =
          CertificatesHandler.defaultAccountDirectoryName,
      String privateKeyPEMFileName =
          CertificatesHandler.defaultPrivateKeyPEMFileName,
      String publicKeyPEMFileName =
          CertificatesHandler.defaultPublicKeyPEMFileName,
      String fullChainPEMFileName =
          CertificatesHandler.defaultFullChainPEMFileName})
      : super(
            accountDirectory: accountDirectory,
            privateKeyPEMFileName: privateKeyPEMFileName,
            publicKeyPEMFileName: publicKeyPEMFileName,
            fullChainPEMFileName: fullChainPEMFileName) {
    directory.createSync(recursive: true);
  }

  @override
  FutureOr<SecurityContext?> buildSecurityContext(String domain) {
    var fullChainFile = fileDomainFullChainPEM(domain);
    var privateKeyFile = fileDomainPrivateKeyPEM(domain);

    if (!_fileExistsWithContent(fullChainFile) ||
        !_fileExistsWithContent(privateKeyFile)) {
      return null;
    }

    var fullChainPath = fullChainFile.path;
    var privateKeyPath = privateKeyFile.path;

    var securityContext = SecurityContext();

    securityContext.useCertificateChain(fullChainPath);
    securityContext.usePrivateKey(privateKeyPath);

    return securityContext;
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
    var file = fileAccountPrivateKeyPEM();
    return _readFileWithContent(file);
  }

  @override
  FutureOr<String?> loadAccountPublicKeyPEM() {
    var file = fileAccountPublicKeyPEM();
    return _readFileWithContent(file);
  }

  @override
  FutureOr<String?> loadDomainPrivateKeyPEM(String cn) {
    var file = fileDomainPrivateKeyPEM(cn);
    return _readFileWithContent(file);
  }

  @override
  FutureOr<String?> loadDomainPublicKeyPEM(String cn) {
    var file = fileDomainPublicKeyPEM(cn);
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
    var filePrivateKey = fileAccountPrivateKeyPEM();
    var filePublicKey = fileAccountPublicKeyPEM();

    return _generateStoredKeyPair(filePrivateKey, filePublicKey, force);
  }

  @override
  Future<PEMKeyPair?> generateDomainPEMKeyPair(String cn,
      {bool force = false}) async {
    var filePrivateKey = fileDomainPrivateKeyPEM(cn);
    var filePublicKey = fileDomainPublicKeyPEM(cn);

    return _generateStoredKeyPair(filePrivateKey, filePublicKey, force);
  }

  Future<PEMKeyPair?> _generateStoredKeyPair(
      File filePrivateKey, File filePublicKey, bool force) async {
    if (!force &&
        (_fileExistsWithContent(filePrivateKey) ||
            _fileExistsWithContent(filePublicKey))) {
      return getAccountPEMKeyPair();
    }

    PEMKeyPair keyPair = generatePEMKeyPair();

    filePrivateKey.parent.createSync(recursive: true);
    filePublicKey.parent.createSync(recursive: true);

    filePrivateKey.writeAsStringSync(keyPair.privateKeyPEM);
    filePublicKey.writeAsStringSync(keyPair.publicKeyPEM);

    return keyPair;
  }

  @override
  PEMKeyPair generatePEMKeyPair() {
    var rsaKeyPair = CryptoUtils.generateRSAKeyPair();

    var rsaPrivateKey = rsaKeyPair.privateKey as RSAPrivateKey;
    var rsaPublicKey = rsaKeyPair.publicKey as RSAPublicKey;

    var privateKeyPEM = CryptoUtils.encodeRSAPrivateKeyToPem(rsaPrivateKey);
    var publicKeyPEM = CryptoUtils.encodeRSAPublicKeyToPem(rsaPublicKey);

    var keyPair =
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
    var domainKeyPair = await getDomainPEMKeyPair(cn);
    if (domainKeyPair == null) {
      return null;
    }

    var attributes = {
      'CN': cn,
      if (organizationName != null) 'O': organizationName,
      if (organizationUnit != null) 'OU': organizationUnit,
      if (locality != null) 'L': locality,
      if (state != null) 'ST': state,
      if (country != null) 'C': country,
    };

    var csr = X509Utils.generateRsaCsrPem(
        attributes, domainKeyPair.privateKey, domainKeyPair.publicKey);

    return csr;
  }

  @override
  Future<bool> saveSignedCertificateChain(
      String cn, List<String> signedCertificatesChain) async {
    String fullChainPEM = CertificatesHandler.joinPEMs(signedCertificatesChain);

    var filePrivateKey = fileDomainFullChainPEM(cn);

    filePrivateKey.parent.createSync(recursive: true);
    filePrivateKey.writeAsStringSync(fullChainPEM);

    return true;
  }
}

class PEMKeyPair {
  final String privateKeyPEM;
  final String publicKeyPEM;

  PEMKeyPair(this.privateKeyPEM, this.publicKeyPEM,
      [this._privateKey, this._publicKey]);

  RSAPrivateKey? _privateKey;

  RSAPrivateKey get privateKey =>
      _privateKey ??= CryptoUtils.rsaPrivateKeyFromPem(privateKeyPEM);

  RSAPublicKey? _publicKey;

  RSAPublicKey get publicKey =>
      _publicKey ??= CryptoUtils.rsaPublicKeyFromPem(publicKeyPEM);
}
