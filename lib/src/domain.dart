/// A [LetsEncrypt] domain.
class Domain {
  /// The domain name. Ex.: your-domain.com
  final String name;

  /// Domain contact e-mail.
  final String email;

  const Domain({required this.name, required this.email});

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
  String toString() => '$name : $email';
}
