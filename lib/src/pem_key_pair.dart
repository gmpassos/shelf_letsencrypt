import 'package:basic_utils/basic_utils.dart';

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
