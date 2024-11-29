import 'dart:io';

import 'certs_handler.dart';

/// A [DomainCertificate] implementation using file paths.
class DomainCertificateFilePath extends DomainCertificate {
  /// The fullChain file path.
  final String fullChainFilePath;

  /// The private key file path.
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
