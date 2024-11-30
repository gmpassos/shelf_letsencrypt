/// A [LetsEncrypt] domain.
class Domain {
  /// The default delimiter for [fromDomainsNamesAndEmailsArgs].
  static RegExp defaultArgDelimiter = RegExp(r'\s*[;:,]\s*');

  /// Splits the arguments [domainNamesArg] and [domainEmailsArg] using the
  /// specified [delimiter] pattern and creates a list of [Domain]s.
  /// - If [delimiter] is not provided, the [defaultArgDelimiter] is used.
  /// - See [fromDomainsNamesAndEmails].
  static List<Domain> fromDomainsNamesAndEmailsArgs(
      String domainNamesArg, String domainEmailsArg,
      {RegExp? delimiter}) {
    delimiter ??= defaultArgDelimiter;

    final domainNames = domainNamesArg.split(delimiter);
    final domainEmails = domainEmailsArg.split(delimiter);

    return fromDomainsNamesAndEmails(domainNames, domainEmails);
  }

  /// Generates a list of [Domain] instances from pairs in the sequence of
  /// [domainNames] and [domainEmails].
  static List<Domain> fromDomainsNamesAndEmails(
      List<String> domainNames, List<String> domainEmails) {
    if (domainNames.length != domainEmails.length) {
      throw ArgumentError(
          "The number of domain names (${domainNames.length}) doesn't match the number of domain emails (${domainEmails.length}).");
    }

    var domains = List.generate(
      domainNames.length,
      (i) => Domain(name: domainNames[i], email: domainEmails[i]),
    );

    return domains;
  }

  /// The domain name. Ex.: your-domain.com
  final String name;

  /// Domain contact e-mail.
  final String email;

  const Domain({required this.name, required this.email});

  static final regexpDomainName = RegExp(
      r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)([A-Za-z0-9-]{1,63})(\.[A-Za-z]{2,})?$');

  bool get isValidName => regexpDomainName.hasMatch(name);

  /// Returns the domain names as a comma separated list
  static String toNames(List<Domain> domains) =>
      domains.map((domain) => domain.name).toList().join(', ');

  static List<String> asStrings(List<Domain> domains) =>
      domains.map((domain) => domain.name).toList();

  /// true if the list of [domains] contains a domain with
  /// a name of [name]
  static bool contains(List<Domain> domains, String name) =>
      domains.any((domain) => domain.name == name);

  @override
  String toString() => '$name: $email';
}
