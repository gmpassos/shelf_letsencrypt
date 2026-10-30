## 2.0.8

- Fix: the library compiles for the web again (broken since 2.0.4): the
  `dart:ffi` POSIX calls of the private-key storage are behind a conditional
  import (`if (dart.library.ffi)`). Without it (the web) `Posix.current()` is
  `null`, as on Windows: POSIX modes are not applied. A package importing
  `shelf_letsencrypt` from code also compiled with dart2js (like `bones_api`'s
  browser tests) failed with `Dart library 'dart:ffi' is not available on
  this platform`.
- Tests: the library compiles with dart2js.
- CI: tests on Windows too.

## 2.0.7

- CLI: an error without a path no longer prints a trailing `: `.
- Tests: the CLI defaults (stdout, stderr, `LetsEncrypt`, shutdown signals),
  the challenge server, an expired served certificate, and a renewal failing
  while serving. Line coverage from 94.2% to 95.8%.

## 2.0.6

- New command-line tool `shelf_letsencrypt` (see the README):
  - `check`: checks the certificates directory like the server does at
    startup, read-only unless `--fix` is given.
  - `list` and `show`: stored domains, certificate expiry and status.
  - `request` and `renew`: obtain certificates, answering the HTTP-01
    challenge themselves. `renew` has `--dry-run`, `--pre-hook` and
    `--post-hook` for cron.
  - `rotate-key`: a new domain key and certificate, restoring the previous
    ones if the request fails.
  - `verify`: checks the certificate a live server serves, and with `--dir`
    that it is the stored one.
  - `serve`: an HTTPS server with automatic certificates and renewals. It
    restarts only for a renewed certificate that loads, and retries a failed
    restart at the next check.
  - `check`, `list`, `show` and `verify` never create or change files.
  - `--json` output, `--verbose` ACME log, and exit codes `0`/`1`/`64`.
  - Uses the staging API unless `--production` is given.
  - args: ^2.6.0
  - shelf_static: ^1.1.3

- `CertificatesHandlerIO`:
  - `CertificatesHandlerIO.readOnly`: opens a directory without creating or
    changing anything. Storage checks still apply; writes throw `StateError`.
  - `inspectStorage`: runs the storage checks of the constructor and of key
    loading without creating or changing anything, and returns the changes a
    handler would make.
  - `listDomains`: the domains with a directory in storage, whether or not
    their certificate is complete and valid.

## 2.0.5

- Security: `CertificatesHandlerIO` no longer follows symbolic links or
  junctions inside the storage directory when writing public keys and
  certificate chains. A link left in an older, writable store could previously
  redirect these writes outside it.
  - Directories on the managed path must be real directories owned by the
    service user; missing ones are created `0700`.
  - Managed public keys and chains are staged and renamed into place, so a
    hard link left at the destination is replaced instead of written through.
  - Configured absolute paths outside the storage directory are unchanged.
  - On Windows, `directory` now also has symbolic links resolved.
  - If the storage directory is removed and its path now resolves elsewhere,
    it is no longer re-created at the new location before the error.

- Tests: account-initialization fallback, key/CSR generation and save
  failures, unloadable certificates after a request or renewal, hard-linked
  public keys, and linked private-key directories.

## 2.0.4

- Security: validate certificate domain names before building filesystem paths
  (GHSA-j4rv-3cg2-g9xc). A domain such as `../outside` could previously read or
  write keys and certificates outside the certificates directory.

- Security: store private keys owner-only (GHSA-vpwj-w7xm-f2p4). On Linux,
  Android, macOS and iOS, `CertificatesHandlerIO` creates certificate
  directories as `0700` and keys as `0600`, and tightens existing ones. Keys
  that may already have been read by another user should be rotated.
  - Construction fails if the storage directory is owned by another user, if an
    ancestor is writable by group or others (unless sticky, like `/tmp`), or if
    a symbolic link in the path is owned by neither root nor the service user.
  - Loading a key fails if it is a symbolic link, has another owner or has
    extra hard links.
  - The storage directory and configured PEM paths cannot contain `..`.
  - `directory` is now the absolute storage path with symbolic links resolved.
  - Generating a key pair throws `StateError` if only one of the two key files
    exists, or if they do not match, instead of returning the account key pair.
  - Windows is unchanged: keys inherit the storage directory's ACLs.
  - Linux requires `statx` (glibc 2.28+, musl 1.2.5+ or Android API 30+).
  - ffi: ^2.1.2

- `Domain.isValidName`:
  - Accepts any number of labels (e.g. `api.dev.example.com`), with the DNS
    limits of 63 characters per label and 253 in total.
  - Rejects all-numeric top-level labels, so IP addresses such as `1.2.3.4`
    are not valid domains.
  - `startServer` no longer silently drops domains with 4 or more labels.

- `CertificatesHandlerIO`:
  - `fileDomain*PEM`, `isHandledDomainCertificate`, `loadDomain*PEM`,
    `generateDomainPEMKeyPair`, `saveSignedCertificateChain` and
    `buildSecurityContexts` throw `ArgumentError` for an invalid domain name
    (previously `buildSecurityContexts` treated it as unresolved).
  - `listAllHandledDomains` ignores directories whose name is not a valid
    domain, and symlinked domain directories.
  - `listAllHandledDomains` supports PEM file names in subdirectories.

- `LetsEncrypt.requestCertificate`: throws `ArgumentError` for an invalid
  domain name before creating any account or domain keys.

- `LetsEncrypt`:
  - `startServer`: no longer modifies the given `domains` list (it threw
    `UnsupportedError` for an unmodifiable list with an invalid domain).
  - `startServer`: closes the servers it started when it fails, instead of
    leaving the HTTP port bound.
  - `getURL`: closes its `HttpClient` and uses a 30s connection timeout.
  - `doACMEChallenge`: throws `StateError` when the order can't be created,
    and always removes the challenge token when it finishes.
  - The ACME account fallback now applies the account it finds or creates
    (the order used to fail with a null-check error), uses a fresh nonce
    instead of replaying a spent one (rejected with `badNonce`), and also runs
    when the client initialization ends without an account.
  - Challenge tokens are matched case-insensitively, so a domain such as
    `WWW.Example.com` passes the HTTP-01 challenge and self-test.

- `CertificatesHandler.buildSecurityContexts`: fixed the documentation of
  `allowUnresolvedDomain`, which described the opposite behaviour.

- Example: the renewal service restarts the current servers. It used to close
  the first servers again, failing on the next renewal. A failed restart is
  retried on the next check.

- Tests:
  - Integration tests of the full ACME flow (issuance, reuse, renewal, SNI
    with multiple domains and every failure path) against an in-process fake
    ACME server with real HTTP-01 validation and nonce checks.
  - Line coverage from 61% to over 93%; CI runs on Linux and macOS and fails
    below 90%.

## 2.0.3

- multi_domain_secure_server: ^1.0.16

## 2.0.2

- sdk: '>=3.5.0 <4.0.0'

- multi_domain_secure_server: ^1.0.14
- basic_utils: ^5.8.2
- collection: ^1.19.0

- dependency_validator: ^5.0.3
- coverage: ^1.15.0
- lints: ^5.1.1
- test: ^1.28.0

## 2.0.1

- multi_domain_secure_server: ^1.0.12

## 2.0.0

- `LetsEncrypt`:
  - `startServer`: ignore invalid domains.
  - `startServer`:
    - Added parameter `v6Only`.
    - Use `MultiDomainSecureServer` if multiple domains are being served:
      - Utilize `MultiDomainSecureServer.asHttpServer()` to provide an `HttpServer` instance for `shelf.serveRequests`.
      - `MultiDomainSecureServer`:
        - Pass `requiresHandshakesWithHostname: true`.
        - Ensure that `HttpServer.listenOn` receives requests from a `SecureSocket`.

- `Domain`:
  - Added `isValidName`.

- multi_domain_secure_server: ^1.0.10
- dependency_validator: ^4.1.2
- coverage: ^1.11.1
- lints: ^4.0.0
- test: ^1.25.12

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
