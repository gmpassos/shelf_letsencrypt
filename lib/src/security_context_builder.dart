import 'dart:io';

import 'certs_handler.dart';

/// A [SecurityContext] builder.
class SecurityContextBuilder {
  final Set<DomainCertificate> domainsCertificates;

  SecurityContextBuilder([Iterable<DomainCertificate>? domainsCertificates])
      : domainsCertificates = domainsCertificates?.toSet() ?? {};

  Map<String, SecurityContext> buildAll() {
    var entries = domainsCertificates
        .expand((domainCertificate) {
          var securityContext = SecurityContext();
          domainCertificate.define(securityContext);
          return domainCertificate.domains
              .map((domain) => MapEntry(domain, securityContext));
        })
        .toSet()
        .toList();

    return Map.fromEntries(entries);
  }
}
