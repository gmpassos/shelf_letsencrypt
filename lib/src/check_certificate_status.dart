// ignore_for_file: avoid_catches_without_on_clauses

import 'package:shelf_letsencrypt/src/letsencrypt.dart';

/// The [LetsEncrypt.checkCertificate] status.
enum CheckCertificateStatus {
  ok,
  okRefreshed,
  invalid,
  error,
}

extension CheckCertificateStatusExtension on CheckCertificateStatus {
  /// Returns `true` if is `ok` or `okRefreshed`.
  bool get isOK =>
      this == CheckCertificateStatus.ok ||
      this == CheckCertificateStatus.okRefreshed;

  /// Returns: ![isOK]
  bool get isNotOK => !isOK;

  /// Returns `true` if is `okRefreshed`.
  bool get isOkRefreshed => this == CheckCertificateStatus.okRefreshed;
}
