import 'package:basic_utils/basic_utils.dart';

/// A PEM Key pair (private/public).
class PEMKeyPair {
  /// PEM of the private key.
  final String privateKeyPEM;

  /// PEM of the public key.
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
