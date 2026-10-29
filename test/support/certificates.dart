import 'dart:io';

import 'package:basic_utils/basic_utils.dart' hide Domain;
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

/// Stores a self-signed certificate for [cn] in [handler], valid for [days].
Future<void> storeSelfSignedCertificate(
    CertificatesHandlerIO handler, String cn,
    {int days = 30}) async {
  final keyPair = await handler.ensureDomainPEMKeyPair(cn);
  final csr = (await handler.generateCSR(cn, 'contact@$cn'))!;
  final certificate =
      X509Utils.generateSelfSignedCertificate(keyPair.privateKey, csr, days);
  await handler.saveSignedCertificateChain(cn, [certificate]);
}

/// A self-signed certificate for [cn], valid for [days] (negative: expired).
({String privateKeyPEM, String certificatePEM}) selfSignedCertificate(String cn,
    {int days = 30}) {
  final keyPair = CryptoUtils.generateRSAKeyPair();
  final privateKey = keyPair.privateKey as RSAPrivateKey;
  final publicKey = keyPair.publicKey as RSAPublicKey;
  final csr = X509Utils.generateRsaCsrPem({'CN': cn}, privateKey, publicKey);
  return (
    privateKeyPEM: CryptoUtils.encodeRSAPrivateKeyToPem(privateKey),
    certificatePEM:
        X509Utils.generateSelfSignedCertificate(privateKey, csr, days),
  );
}

/// Creates the hard link [link] to [target] (POSIX only).
void hardLink(String target, String link) {
  final result = Process.runSync('ln', [target, link]);
  if (result.exitCode != 0) {
    throw FileSystemException('ln failed: ${result.stderr}', link);
  }
}
