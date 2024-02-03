import 'dart:io';

import 'certs_handler.dart';

/// A [SecurityContext] builder.
class SecurityContextBuilder {
  static bool defineMerged = false;

  final Set<DomainCertificate> domainsCertificates = <DomainCertificate>{};

  SecurityContext build() {
    final securityContext = SecurityContext();

    if (defineMerged) {
      domainsCertificates
          .reduce((value, element) => value.merge(element))
          .define(securityContext);
    } else {
      for (final d in domainsCertificates) {
        d.define(securityContext);
      }
    }

    return securityContext;
  }
}
