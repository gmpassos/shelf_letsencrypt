import 'posix_stat.dart';

/// Without `dart:ffi` (the web): no POSIX calls.
final class Posix {
  Posix._();

  /// Always `null`: like Windows, POSIX modes are not applied.
  static Posix? current() => null;

  int get euid => throw UnsupportedError('No `dart:ffi`');

  PosixStat lstat(String path) => throw UnsupportedError('No `dart:ffi`');

  void chmod(String path, int mode) => throw UnsupportedError('No `dart:ffi`');

  void mkdir(String path, int mode) => throw UnsupportedError('No `dart:ffi`');
}
