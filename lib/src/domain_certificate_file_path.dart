import 'dart:io';

import '../shelf_letsencrypt.dart';
import 'certs_handler.dart';

/// A [DomainCertificate] implementation using file paths.
class DomainCertificateFilePath extends DomainCertificate {
  final String fullChainFilePath;

  final String privateKeyFilePath;

  DomainCertificateFilePath(List<String> super.domains, this.fullChainFilePath,
      this.privateKeyFilePath);

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
