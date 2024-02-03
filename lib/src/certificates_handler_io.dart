import 'dart:async';
import 'dart:io';

import 'package:basic_utils/basic_utils.dart' hide Domain;
import 'package:collection/collection.dart';
import 'package:path/path.dart' as pack_path;

import 'certs_handler.dart';
import 'domain.dart';
import 'domain_certificate_file_path.dart';
import 'pem_key_pair.dart';
import 'security_context_builder.dart';

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
  Future<SecurityContext?> buildSecurityContext(List<Domain> domains,
      {bool loadAllHandledDomains = true}) async {
    final securityContextBuilder = SecurityContextBuilder();

    for (final domain in domains) {
      final domainOk =
          await _useDomainCertificate(securityContextBuilder, domain.name);
      if (!domainOk) {
        return null;
      }
    }

    if (loadAllHandledDomains) {
      final handledDomains = listAllHandledDomains();

      for (final d in handledDomains) {
        if (!Domain.contains(domains, d)) {
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
