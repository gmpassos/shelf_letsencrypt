## 2.0.0-beta.6

- multi_domain_secure_server: ^1.0.8

## 2.0.0-beta.5

- `LetsEncrypt`:
  - `startServer`: use `secureServer.asHttpServer()`

- multi_domain_secure_server: ^1.0.7

## 2.0.0-beta.4

- `LetsEncrypt`:
  - `startServer`:
    - `MultiDomainSecureServer`:
      - Pass `requiresHandshakesWithHostname: true`.
      - Ensure that `HttpServer.listenOn` receives requests from a `SecureSocket`.

- multi_domain_secure_server: ^1.0.6

## 2.0.0-beta.3

- `Domain`:
  - Added `isValidName`.

- `LetsEncrypt`:
  - `startServer`: ignore invalid domains.

## 2.0.0-beta.2

- `LetsEncrypt`:
  - `startServer`:
    - Added parameter `v6Only`.
    - Use `MultiDomainSecureServer` if multiple domains are being served.

- multi_domain_secure_server: ^1.0.5
- dependency_validator: ^4.1.1

## 2.0.0-beta.1

- BREAKING: Moved the port, securePort and bindingAddress from the startServer
  method to the LetsEncrypt constructor.
- Added new version of startServer which takes a list of Domains rather than a
  map of domain/emails. This should make
  the API clearer.
- Deprecated startSecureServer in favour of startServer. startSecureServer will be removed in `v2.1.0`.
- Fixed a number of bugs where an alternate port was being ignored.

- `SecurityContextBuilder`:
  - Changed `build` to `buildAll`, returning a `Map<String, SecurityContext>`.

- `LetsEncrypt.startServer`:
  - Now receives a `Map<String, SecurityContext> securityContexts` and an optional `SecurityContext? defaultSecurityContext`.

- acme_client: ^1.3.0
- basic_utils: ^5.7.0
- path: ^1.9.1
- shelf: ^1.4.2

- dependency_validator: ^3.2.3
- coverage: ^1.11.0
- cron: ^0.5.1
- lints: ^3.0.0
- test: ^1.25.9

## 1.2.2

- `LetsEncrypt`:
  - Added feild `minCertificateValidityTime`.
    - `isDomainHttpsOK` now checks the certificate for short validity period,
      allowing to refresh the certificate before it really expires (5 days before as default).
  - Field `log`: improve logging parameters.
  - Improve logging messages.
- Dart CI: update and optimize jobs.

- test: ^1.24.6

## 1.2.1

- acme_client: ^1.2.0
- basic_utils: ^5.6.1
- collection: ^1.18.0
- lints: ^2.1.1
- test: ^1.24.4

## 1.2.0

- `LetsEncrypt`:
  - Rename `isWellknownPath` to `isWellKnownPath```
- sdk: '>=3.0.0 <4.0.0'
- shelf: ^1.4.1
- collection: ^1.17.1
- lints: ^2.1.0
- test: ^1.24.1

## 1.1.1

- Self check URL now handled by `shelf_letsencrypt`:
  - Using path: `/.well-known/check/`

## 1.1.0

- `README.md`: fix Dart CI badge
- Update Dart CI.
- Fix lints.
- path: ^1.8.3
- shelf: ^1.4.0
- acme_client: ^1.1.0
- basic_utils: ^3.9.4
- coverage: ^1.6.3
- collection: ^1.16.0
- lints: ^2.0.1
- test: ^1.23.1
- dependency_validator: ^3.2.2

## 1.0.1

- Added support for multiple domains certificates in the same HTTPS server.
- collection: ^1.15.0

## 1.0.0

- Initial version.
