import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as p;

/// `0700`: managed directories.
const _ownerOnlyDirectory = 0x1c0;

/// `0600`: private keys.
const _ownerOnlyFile = 0x180;

/// Owner-only storage for the IO certificate handler.
///
/// On Linux, Android, macOS and iOS, managed directories are `0700` and private
/// keys `0600`, both owned by the effective user. On Windows POSIX modes do not
/// apply: keys are written without these checks and inherit the ACLs of the
/// storage directory, which must be private to the service account.
///
/// Configuration and ancestors must be controlled by the service operator.
/// This does not defend against another process running as the same user or a
/// process that can replace a trusted ancestor while the service is running.
final class PrivateKeyStorage {
  PrivateKeyStorage(Directory root) : _posix = _Posix.current() {
    final path = p.normalize(root.absolute.path);
    if (_posix == null) {
      Directory(path).createSync(recursive: true);
      _rootPath = path;
    } else {
      _rootPath = _prepareRoot(path);
    }
  }

  final _Posix? _posix;

  /// The storage root with symbolic links resolved. Permission checks and file
  /// operations both use this path.
  late final String _rootPath;

  Directory get root => Directory(_rootPath);

  /// Creates or secures the root at [path] and returns its resolved path.
  String _prepareRoot(String path) {
    final missing = <String>[];
    var existing = path;
    while (FileSystemEntity.typeSync(existing, followLinks: false) ==
        FileSystemEntityType.notFound) {
      missing.add(p.basename(existing));
      final parent = p.dirname(existing);
      if (parent == existing) {
        throw FileSystemException('No existing storage ancestor', existing);
      }
      existing = parent;
    }
    // The managed root itself may be an old 0755 store that needs migration.
    // Its parent and all higher ancestors must already be trusted.
    var current = _resolveTrustedPath(existing, exempt: missing.isEmpty);
    for (final component in missing.reversed) {
      current = p.join(current, component);
      _posix!.mkdir(current, _ownerOnlyDirectory);
      _secureOwnedDirectory(current);
    }
    _secureOwnedDirectory(current);
    return current;
  }

  /// The root was verified at construction. Only re-create it if it has been
  /// removed since.
  void _secureRoot() {
    if (FileSystemEntity.typeSync(_rootPath, followLinks: false) ==
        FileSystemEntityType.notFound) {
      if (_prepareRoot(_rootPath) != _rootPath) {
        throw FileSystemException('Storage root has moved', _rootPath);
      }
    } else {
      _secureOwnedDirectory(_rootPath);
    }
  }

  /// Verifies [path] and its ancestors, then verifies and returns [path] with
  /// symbolic links resolved. With [exempt], [path] itself may be writable by
  /// others because the caller secures it next.
  String _resolveTrustedPath(String path, {bool exempt = false}) {
    _verifyTrustedComponents(path, exempt: exempt);
    final resolved = p.normalize(Directory(path).resolveSymbolicLinksSync());
    if (resolved != path) {
      _verifyTrustedComponents(resolved, exempt: exempt);
    }
    return resolved;
  }

  void _verifyTrustedComponents(String path, {required bool exempt}) {
    final posix = _posix!;
    var current = path;
    var first = true;
    while (true) {
      final status = posix.lstat(current);
      if (status.isLink) {
        // Whoever owns a link decides where it points, so only root or the
        // service user may own one (e.g. `/var -> private/var` on macOS).
        if (status.uid != 0 && status.uid != posix.euid) {
          throw FileSystemException(
              'Storage path contains an untrusted symbolic link', current);
        }
      } else if (!status.isDirectory) {
        throw FileSystemException(
            'Storage ancestor is not a directory', current);
      } else if (!(first && exempt)) {
        final writeByOthers = (status.permissions & 0x12) != 0;
        // A sticky shared parent (normally /tmp) protects a service-owned
        // child from other users. The parent owner is part of trusted storage
        // configuration and must not be an attacker.
        if (writeByOthers && !status.isSticky) {
          throw FileSystemException(
              'Storage ancestor is writable by others', current);
        }
      }
      first = false;
      final parent = p.dirname(current);
      if (parent == current) return;
      current = parent;
    }
  }

  void _secureOwnedDirectory(String path) {
    final posix = _posix!;
    final status = posix.lstat(path);
    if (!status.isDirectory) {
      throw FileSystemException(
          'Certificate directory is not a directory', path);
    }
    if (status.uid != posix.euid) {
      throw FileSystemException(
          'Certificate directory has a different owner', path);
    }
    if (status.permissions != _ownerOnlyDirectory) {
      posix.chmod(path, _ownerOnlyDirectory);
    }
    final secured = posix.lstat(path);
    if (secured.uid != posix.euid ||
        !secured.isDirectory ||
        secured.permissions != _ownerOnlyDirectory) {
      throw FileSystemException(
          'Certificate directory is not owner-only', path);
    }
  }

  void _preparePrivateParent(Directory parent) {
    final posix = _posix!;
    final parentPath = p.normalize(parent.absolute.path);
    if (parentPath == _rootPath || p.isWithin(_rootPath, parentPath)) {
      _secureRoot();
      var current = _rootPath;
      final relative = p.relative(parentPath, from: _rootPath);
      if (relative == '.') return;
      for (final component in p.split(relative)) {
        current = p.join(current, component);
        if (FileSystemEntity.typeSync(current, followLinks: false) ==
            FileSystemEntityType.notFound) {
          posix.mkdir(current, _ownerOnlyDirectory);
        }
        _secureOwnedDirectory(current);
      }
    } else {
      // A configured external key location is trusted configuration, but its
      // parent must already be owner-only. Never chmod an unrelated directory.
      final resolved = _resolveTrustedPath(parentPath);
      final status = posix.lstat(resolved);
      if (status.uid != posix.euid ||
          !status.isDirectory ||
          status.permissions != _ownerOnlyDirectory) {
        throw FileSystemException(
            'External private-key directory must be owner-only', parentPath);
      }
    }
  }

  void prepareKeyParent(Directory parent) {
    if (_posix == null) {
      parent.createSync(recursive: true);
    } else {
      _preparePrivateParent(parent);
    }
  }

  /// Tightens an existing private key before it is returned or passed to TLS.
  /// Missing keys remain missing; this method never creates one.
  void secureExistingKey(File file) {
    final posix = _posix;
    if (posix == null) return;
    final type = FileSystemEntity.typeSync(file.path, followLinks: false);
    if (type == FileSystemEntityType.notFound) return;
    _preparePrivateParent(file.parent);
    if (type != FileSystemEntityType.file) {
      throw FileSystemException('Private key is not a regular file', file.path);
    }
    final status = posix.lstat(file.path);
    if (!status.isFile || status.uid != posix.euid || status.nlink != 1) {
      throw FileSystemException(
          'Private key has unsafe owner, type or link count', file.path);
    }
    if (status.permissions != _ownerOnlyFile) {
      posix.chmod(file.path, _ownerOnlyFile);
    }
    final secured = posix.lstat(file.path);
    if (!secured.isFile ||
        secured.uid != posix.euid ||
        secured.nlink != 1 ||
        secured.permissions != _ownerOnlyFile) {
      throw FileSystemException('Private key is not owner-only', file.path);
    }
  }

  void writeKey(File target, String pem) {
    if (_posix == null) {
      target.parent.createSync(recursive: true);
      target.writeAsStringSync(pem, flush: true);
      return;
    }
    _preparePrivateParent(target.parent);
    secureExistingKey(target);
    final random = Random.secure();
    final staging = File(p.join(target.parent.path,
        '.${p.basename(target.path)}.${random.nextInt(1 << 32)}.tmp'));
    staging.createSync(exclusive: true);
    try {
      secureExistingKey(staging);
      staging.writeAsStringSync(pem, flush: true);
      staging.renameSync(target.path);
      secureExistingKey(target);
    } finally {
      if (staging.existsSync()) staging.deleteSync();
    }
  }
}

/// The fields of a file status used by [PrivateKeyStorage].
final class _Stat {
  const _Stat({required this.mode, required this.nlink, required this.uid});

  /// File type and permission bits (`st_mode`).
  final int mode;
  final int nlink;
  final int uid;

  int get permissions => mode & 0x1ff;
  bool get isSticky => (mode & 0x200) != 0;
  bool get isDirectory => (mode & 0xf000) == 0x4000;
  bool get isFile => (mode & 0xf000) == 0x8000;
  bool get isLink => (mode & 0xf000) == 0xa000;
}

/// The POSIX calls used by [PrivateKeyStorage], bound through `dart:ffi`.
///
/// File status is read at fixed offsets: Linux `struct statx` has the same
/// layout on every architecture, and Darwin's 64-bit-inode `struct stat` has
/// the same layout on x86_64 and arm64.
final class _Posix {
  _Posix._(this._darwin);

  /// Returns `null` on Windows, where POSIX modes do not apply.
  static _Posix? current() {
    if (Platform.isWindows) return null;
    if (Platform.isLinux || Platform.isAndroid) return _Posix._(false);
    if (Platform.isMacOS || Platform.isIOS) return _Posix._(true);
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

  _Stat lstat(String path) {
    final cPath = path.toNativeUtf8();
    final buffer = calloc<ffi.Uint8>(_statBufferSize);
    try {
      _check(_lstat(cPath, buffer), 'Cannot read file status', path);
      final data = buffer.asTypedList(_statBufferSize).buffer.asByteData();
      if (_darwin) {
        return _Stat(
            mode: data.getUint16(4, Endian.host),
            nlink: data.getUint16(6, Endian.host),
            uid: data.getUint32(16, Endian.host));
      }
      if ((data.getUint32(0, Endian.host) & _statxMask) != _statxMask) {
        throw FileSystemException('Incomplete file status', path);
      }
      return _Stat(
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
