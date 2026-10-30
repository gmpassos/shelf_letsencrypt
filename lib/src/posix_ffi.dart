import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'posix_stat.dart';

/// The POSIX calls used by `PrivateKeyStorage`, bound through `dart:ffi`.
///
/// File status is read at fixed offsets: Linux `struct statx` has the same
/// layout on every architecture, and Darwin's 64-bit-inode `struct stat` has
/// the same layout on x86_64 and arm64.
final class Posix {
  Posix._(this._darwin);

  /// Returns `null` on Windows, where POSIX modes do not apply.
  static Posix? current() {
    if (Platform.isWindows) return null;
    if (Platform.isLinux || Platform.isAndroid) return Posix._(false);
    if (Platform.isMacOS || Platform.isIOS) return Posix._(true);
    throw UnsupportedError('CertificatesHandlerIO has no private-key storage '
        'backend for ${Platform.operatingSystem}');
  }

  /// `STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID`.
  static const _statxMask = 0xf;

  /// Large enough for Linux `struct statx` (256) and Darwin `struct stat`.
  static const _statBufferSize = 256;

  final bool _darwin;
  final _libc = ffi.DynamicLibrary.process();

  late final int euid =
      _libc.lookupFunction<ffi.Uint32 Function(), int Function()>('geteuid')();

  // `mode_t` is 16 bits on Darwin and 32 bits on Linux.
  late final int Function(ffi.Pointer<Utf8>, int) _chmod = _darwin
      ? _libc.lookupFunction<ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Uint16),
          int Function(ffi.Pointer<Utf8>, int)>('chmod')
      : _libc.lookupFunction<ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Uint32),
          int Function(ffi.Pointer<Utf8>, int)>('chmod');

  late final int Function(ffi.Pointer<Utf8>, int) _mkdir = _darwin
      ? _libc.lookupFunction<ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Uint16),
          int Function(ffi.Pointer<Utf8>, int)>('mkdir')
      : _libc.lookupFunction<ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Uint32),
          int Function(ffi.Pointer<Utf8>, int)>('mkdir');

  late final int Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>) _lstat =
      _darwin ? _darwinLStat() : _linuxStatx();

  late final ffi.Pointer<ffi.Int32> Function() _errnoLocation =
      _libc.lookupFunction<ffi.Pointer<ffi.Int32> Function(),
              ffi.Pointer<ffi.Int32> Function()>(
          _darwin
              ? '__error'
              : (Platform.isAndroid ? '__errno' : '__errno_location'));

  int Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>) _darwinLStat() {
    // On x86_64 the plain `lstat` symbol has the legacy 32-bit-inode layout.
    final name =
        ffi.Abi.current() == ffi.Abi.macosX64 ? r'lstat$INODE64' : 'lstat';
    return _libc.lookupFunction<
        ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>),
        int Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>)>(name);
  }

  int Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>) _linuxStatx() {
    if (!_libc.providesSymbol('statx')) {
      throw UnsupportedError('CertificatesHandlerIO requires statx '
          '(glibc 2.28+, musl 1.2.5+ or Android API 30+)');
    }
    final statx = _libc.lookupFunction<
        ffi.Int32 Function(ffi.Int32, ffi.Pointer<Utf8>, ffi.Int32, ffi.Uint32,
            ffi.Pointer<ffi.Uint8>),
        int Function(
            int, ffi.Pointer<Utf8>, int, int, ffi.Pointer<ffi.Uint8>)>('statx');
    const atFdCwd = -100;
    const atSymlinkNoFollow = 0x100;
    return (path, buffer) =>
        statx(atFdCwd, path, atSymlinkNoFollow, _statxMask, buffer);
  }

  PosixStat lstat(String path) {
    final cPath = path.toNativeUtf8();
    final buffer = calloc<ffi.Uint8>(_statBufferSize);
    try {
      _check(_lstat(cPath, buffer), 'Cannot read file status', path);
      final data = buffer.asTypedList(_statBufferSize).buffer.asByteData();
      if (_darwin) {
        return PosixStat(
            mode: data.getUint16(4, Endian.host),
            nlink: data.getUint16(6, Endian.host),
            uid: data.getUint32(16, Endian.host));
      }
      if ((data.getUint32(0, Endian.host) & _statxMask) != _statxMask) {
        throw FileSystemException('Incomplete file status', path);
      }
      return PosixStat(
          mode: data.getUint16(28, Endian.host),
          nlink: data.getUint32(16, Endian.host),
          uid: data.getUint32(20, Endian.host));
    } finally {
      calloc.free(buffer);
      calloc.free(cPath);
    }
  }

  void chmod(String path, int mode) => _withPath(
      path, (cPath) => _check(_chmod(cPath, mode), 'Cannot chmod', path));

  void mkdir(String path, int mode) => _withPath(
      path,
      (cPath) => _check(_mkdir(cPath, mode),
          'Cannot create private certificate directory', path));

  void _withPath(String path, void Function(ffi.Pointer<Utf8>) call) {
    final cPath = path.toNativeUtf8();
    try {
      call(cPath);
    } finally {
      calloc.free(cPath);
    }
  }

  void _check(int result, String message, String path) {
    if (result != 0) {
      throw FileSystemException(
          message, path, OSError('', _errnoLocation().value));
    }
  }
}
