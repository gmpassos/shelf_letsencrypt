import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';

import '../certificates_handler_io.dart';
import '../certs_handler.dart';

/// The fields of a certificate shown by the CLI.
class CertificateInfo {
  CertificateInfo._(this.pem, this.subject, this.names, this.issuer,
      this.notBefore, this.notAfter, this.serialNumber, this.chainLength);

  /// Parses the first certificate of the PEM chain [pemChain].
  /// Throws [FormatException] if it does not start with a certificate.
  factory CertificateInfo.parse(String pemChain) {
    final List<String> pems;
    final X509CertificateData data;
    try {
      // `splitPEMs` asserts on text outside PEM blocks.
      pems = CertificatesHandler.splitPEMs(pemChain);
      if (pems.isEmpty) throw const FormatException('No PEM block');
      data = X509Utils.x509CertificateFromPem(pems.first);
    } catch (e) {
      throw FormatException('Invalid certificate: $e');
    }
    final tbs = data.tbsCertificate;
    if (tbs == null) throw const FormatException('Invalid certificate');
    return CertificateInfo._(
        pems.first,
        tbs.subject['2.5.4.3'] ?? '',
        tbs.extensions?.subjectAlternativNames ?? const [],
        tbs.issuer['2.5.4.3'] ??
            tbs.issuer.values.whereType<String>().join(', '),
        tbs.validity.notBefore,
        tbs.validity.notAfter,
        tbs.serialNumber,
        pems.length);
  }

  /// The first certificate of the chain, in PEM format.
  final String pem;

  /// The common name of the subject.
  final String subject;

  /// The subject alternative names.
  final List<String> names;

  /// The common name of the issuer.
  final String issuer;

  final DateTime notBefore;
  final DateTime notAfter;
  final BigInt serialNumber;

  /// The number of certificates in the chain.
  final int chainLength;

  /// Whole days left until [notAfter]; negative once expired.
  int daysLeft(DateTime now) => notAfter.difference(now).inDays;

  /// The DER bytes of [pem], to compare with a served certificate.
  Uint8List get der => base64.decode(pem
      .replaceAll(RegExp(r'-----[A-Z ]+-----'), '')
      .replaceAll(RegExp(r'\s'), ''));

  Map<String, Object?> toJson() => {
        'subject': subject,
        'names': names,
        'issuer': issuer,
        'notBefore': notBefore.toUtc().toIso8601String(),
        'notAfter': notAfter.toUtc().toIso8601String(),
        'serialNumber': serialNumber.toRadixString(16),
        'chainLength': chainLength,
      };
}

/// The state of a stored domain certificate.
enum CertificateState {
  /// Valid for more than the renewal window.
  ok,

  /// Valid, but expires within the renewal window.
  expiring,

  /// Past its expiry date, or not valid yet.
  expired,

  /// The certificate chain or private key is missing.
  missing,

  /// The certificate chain can't be parsed.
  invalid,
}

/// A stored domain certificate and its [state].
class DomainCertificateStatus {
  DomainCertificateStatus(this.domain, this.state, [this.info, this.error]);

  /// Reads the certificate of [domain] stored by [handler]. A certificate
  /// expiring within [renewDays] is [CertificateState.expiring].
  factory DomainCertificateStatus.read(
      CertificatesHandlerIO handler, String domain,
      {required int renewDays, DateTime? now}) {
    final chain = handler.fileDomainFullChainPEM(domain);
    final key = handler.fileDomainPrivateKeyPEM(domain);
    if (!_hasContent(chain) || !_hasContent(key)) {
      return DomainCertificateStatus(domain, CertificateState.missing);
    }
    final CertificateInfo info;
    try {
      info = CertificateInfo.parse(chain.readAsStringSync());
    } on FormatException catch (e) {
      return DomainCertificateStatus(
          domain, CertificateState.invalid, null, e.message);
    }
    now ??= DateTime.now();
    final state = now.isBefore(info.notBefore) || !now.isBefore(info.notAfter)
        ? CertificateState.expired
        : info.daysLeft(now) < renewDays
            ? CertificateState.expiring
            : CertificateState.ok;
    return DomainCertificateStatus(domain, state, info);
  }

  final String domain;
  final CertificateState state;
  final CertificateInfo? info;
  final String? error;

  /// Whether a certificate should be requested: anything but
  /// [CertificateState.ok].
  bool get isDue => state != CertificateState.ok;

  Map<String, Object?> toJson(DateTime now) => {
        'domain': domain,
        'status': state.name,
        if (info != null) 'daysLeft': info!.daysLeft(now),
        if (info != null) 'certificate': info!.toJson(),
        if (error != null) 'error': error,
      };

  static bool _hasContent(File file) =>
      file.existsSync() && file.lengthSync() > 1;
}
