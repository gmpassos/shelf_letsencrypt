import 'package:acme_client/acme_client.dart';

import 'letsencrypt.dart';

/// A prepared `dns-persist-01` request waiting for the caller to publish the
/// TXT record before certificate issuance can continue.
///
/// Typical flow:
///
/// 1. Call [LetsEncrypt.prepareDnsPersistCertificateRequest].
/// 2. Show [proof] to an operator or publish it through your DNS automation.
/// 3. Once the TXT record is live, call [complete].
class PendingDnsPersistRequest {
  PendingDnsPersistRequest.internal({
    required this.domainName,
    required this.proof,
    required Future<bool> Function({bool forceRequestCertificate}) complete,
  }) : _complete = complete;

  /// The domain being validated.
  final String domainName;

  /// The persistent TXT record the user must publish.
  final DnsPersistChallengeProof proof;

  final Future<bool> Function({bool forceRequestCertificate}) _complete;

  Future<bool>? _completion;

  /// Completes validation, finalizes the order, and stores the certificate.
  ///
  /// Call this only after the TXT record from [proof] has been published.
  ///
  /// This method is idempotent for a prepared request unless
  /// [forceRequestCertificate] is `true`. Concurrent calls share the same
  /// in-flight completion, and calls after a successful completion return the
  /// same result. If completion fails or [timeout] expires, a later call retries
  /// the validation/finalization step.
  Future<bool> complete({
    bool forceRequestCertificate = false,
    Duration? timeout,
  }) {
    if (forceRequestCertificate) {
      _completion = null;
      return _completion = _completeOnce(
        forceRequestCertificate: true,
        timeout: timeout,
      );
    }

    final completion = _completion;
    if (completion != null) {
      return completion;
    }

    return _completion = _completeOnce(timeout: timeout);
  }

  Future<bool> _completeOnce({
    bool forceRequestCertificate = false,
    Duration? timeout,
  }) async {
    try {
      final completion = _complete(
        forceRequestCertificate: forceRequestCertificate,
      );
      return await (timeout == null ? completion : completion.timeout(timeout));
    } catch (_) {
      _completion = null;
      rethrow;
    }
  }
}
