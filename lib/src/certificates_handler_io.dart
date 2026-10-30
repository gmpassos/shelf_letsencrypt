import 'dart:async';
import 'dart:io';

import 'package:basic_utils/basic_utils.dart' hide Domain;
import 'package:path/path.dart' as pack_path;

import 'certs_handler.dart';
import 'domain.dart';
import 'domain_certificate_file_path.dart';
import 'pem_key_pair.dart';
import 'private_key_storage.dart';
import 'security_context_builder.dart';

/// A [CertificatesHandler] implementation using [dart:io].
class CertificatesHandlerIO extends CertificatesHandler {
  CertificatesHandlerIO(Directory directory,
      {super.accountDirectory,
      super.privateKeyPEMFileName,
      super.publicKeyPEMFileName,
      super.fullChainPEMFileName}) {
    for (final configuredPath in [
      accountDirectory,
      privateKeyPEMFileName,
      publicKeyPEMFileName,
      fullChainPEMFileName
    ]) {
      if (pack_path.split(configuredPath).any((part) => part == '..')) {
        throw ArgumentError.value(configuredPath, 'configuredPath',
            'Certificate paths cannot contain parent components');
      }
    }
    _storage = PrivateKeyStorage(_checkedStorageDirectory(directory));
  }

  static Directory _checkedStorageDirectory(Directory directory) {
    final absolutePath = directory.absolute.path;
    if (pack_path.split(directory.path).contains('..') ||
        pack_path.split(absolutePath).contains('..')) {
      throw ArgumentError.value(directory.path, 'directory',
          'Certificate storage path cannot contain parent components');
    }
    return Directory(pack_path.normalize(absolutePath));
  }

  /// The [Directory] to storage certificates, as an absolute path with
  /// symbolic links resolved.
  Directory get directory => _storage.root;
  late final PrivateKeyStorage _storage;

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
    if (FileSystemEntity.typeSync(e.path, followLinks: false) !=
        FileSystemEntityType.directory) {
      return false;
    }

    final dirName = _pathFileName(e.path);

    if (dirName == accountDirectory ||
        !Domain(name: dirName, email: '').isValidName) {
      return false;
    }
    // Configured PEM filenames can contain subdirectories. The caller checks
    // whether a complete certificate exists after this directory filter.
    return true;
  }

  String _pathFileName(String path) => pack_path.split(path).last;

  @override
  Future<Map<String, SecurityContext>?> buildSecurityContexts(
      List<Domain> domains,
      {bool allowUnresolvedDomain = false,
      bool loadAllHandledDomains = true}) async {
    for (final domain in domains) {
      _checkedDomain(domain.name);
    }
    final securityContextBuilder = SecurityContextBuilder();

    var resolvedDomains = <Domain>{};
    var unresolvedDomains = <Domain>{};

    for (final domain in domains) {
      final domainOk =
          await _useDomainCertificate(securityContextBuilder, domain.name);
      if (domainOk) {
        resolvedDomains.add(domain);
      } else {
        unresolvedDomains.add(domain);
      }
    }

    if (unresolvedDomains.isNotEmpty && !allowUnresolvedDomain) {
      return null;
    }

    if (loadAllHandledDomains) {
      final handledDomains = listAllHandledDomains();

      for (final d in handledDomains) {
        if (!Domain.contains(domains, d)) {
          await _useDomainCertificate(securityContextBuilder, d);
        }
      }
    }

    final securityContexts = securityContextBuilder.buildAll();
    return securityContexts;
  }

  Future<bool> _useDomainCertificate(
      SecurityContextBuilder securityContextBuilder, String domain) async {
    final fullChainFile = fileDomainFullChainPEM(domain);
    final privateKeyFile = fileDomainPrivateKeyPEM(domain);
    _storage.secureExistingKey(privateKeyFile);

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
    _storage.secureExistingKey(privateKeyFile);

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

  File fileDomainPrivateKeyPEM(String cn) => File(pack_path.join(
      directory.path, _checkedDomain(cn), privateKeyPEMFileName));

  File fileDomainPublicKeyPEM(String cn) => File(
      pack_path.join(directory.path, _checkedDomain(cn), publicKeyPEMFileName));

  File fileDomainFullChainPEM(String cn) => File(
      pack_path.join(directory.path, _checkedDomain(cn), fullChainPEMFileName));

  String _checkedDomain(String cn) {
    if (!Domain(name: cn, email: '').isValidName) {
      throw ArgumentError.value(cn, 'cn', 'Invalid domain name');
    }
    return cn;
  }

  @override
  FutureOr<String?> loadAccountPrivateKeyPEM() {
    final file = fileAccountPrivateKeyPEM();
    _storage.secureExistingKey(file);
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
    _storage.secureExistingKey(file);
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

    return _generateStoredKeyPair(
        filePrivateKey, filePublicKey, force, getAccountPEMKeyPair);
  }

  @override
  Future<PEMKeyPair?> generateDomainPEMKeyPair(String cn,
      {bool force = false}) async {
    final filePrivateKey = fileDomainPrivateKeyPEM(cn);
    final filePublicKey = fileDomainPublicKeyPEM(cn);

    return _generateStoredKeyPair(
        filePrivateKey, filePublicKey, force, () => getDomainPEMKeyPair(cn));
  }

  Future<PEMKeyPair?> _generateStoredKeyPair(
      File filePrivateKey,
      File filePublicKey,
      bool force,
      Future<PEMKeyPair?> Function() loadExisting) async {
    _storage.secureExistingKey(filePrivateKey);
    final hasPrivate = _fileExistsWithContent(filePrivateKey);
    final hasPublic = _fileExistsWithContent(filePublicKey);
    if (!force && (hasPrivate || hasPublic)) {
      if (!hasPrivate || !hasPublic) {
        throw StateError('Stored key pair is incomplete');
      }
      final existing = await loadExisting();
      if (existing == null ||
          existing.privateKey.modulus != existing.publicKey.modulus) {
        throw StateError('Stored private and public keys do not match');
      }
      return existing;
    }

    final keyPair = generatePEMKeyPair();
    _storage.prepareKeyParent(filePrivateKey.parent);
    _storage.preparePublicTarget(filePublicKey, 'Public key');
    _storage.writeKey(filePrivateKey, keyPair.privateKeyPEM);
    _storage.writePublic(filePublicKey, keyPair.publicKeyPEM, 'Public key');

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

    _storage.writePublic(filePrivateKey, fullChainPEM, 'Certificate chain');

    return true;
  }

  @override
  String toString() => 'CertificatesHandlerIO@$directory';
}
