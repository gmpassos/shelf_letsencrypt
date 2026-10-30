import 'posix_stat.dart';

/// Without `dart:ffi` (the web): no private-key storage backend.
final class Posix {
  Posix._();

  static Posix? current() =>
      throw UnsupportedError('CertificatesHandlerIO requires `dart:ffi`');

  int get euid => throw UnsupportedError('No `dart:ffi`');

  PosixStat lstat(String path) => throw UnsupportedError('No `dart:ffi`');

  void chmod(String path, int mode) => throw UnsupportedError('No `dart:ffi`');

  void mkdir(String path, int mode) => throw UnsupportedError('No `dart:ffi`');
}
