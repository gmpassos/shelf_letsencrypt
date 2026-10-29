import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:math';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as p;
import 'package:posix/posix.dart' as posix;

/// Owner-only storage for the IO certificate handler on Linux.
///
/// Configuration and ancestors must be controlled by the service operator.
/// This does not defend against another process running as the same user or a
/// process that can replace a trusted ancestor while the service is running.
final class PrivateKeyStorage {
  PrivateKeyStorage(this.root) {
    if (!Platform.isLinux || Platform.isAndroid) {
      throw UnsupportedError(
          'CertificatesHandlerIO requires a private-key storage backend on '
          '${Platform.operatingSystem}; its built-in backend supports Linux only');
    }
    if (!posix.isPosixSupported) {
      throw UnsupportedError('POSIX access control is unavailable');
    }
    _prepareRoot();
  }

  final Directory root;

  String get _rootPath => p.normalize(root.absolute.path);

  int get _owner => posix.geteuid();

  void _prepareRoot() {
    final missing = <String>[];
    var current = _rootPath;
    while (FileSystemEntity.typeSync(current, followLinks: false) ==
        FileSystemEntityType.notFound) {
      missing.add(current);
      final parent = p.dirname(current);
      if (parent == current) {
        throw FileSystemException('No existing storage ancestor', current);
      }
      current = parent;
    }
    // The managed root itself may be an old 0755 store that needs migration.
    // Its parent and all higher ancestors must already be trusted.
    _verifyTrustedAncestors(missing.isEmpty ? p.dirname(_rootPath) : current);
    for (final component in missing.reversed) {
      _mkdirPrivate(component);
      _secureOwnedDirectory(component);
    }
    _secureOwnedDirectory(_rootPath);
  }

  void _verifyTrustedAncestors(String path) {
    var current = path;
    while (true) {
      if (FileSystemEntity.typeSync(current, followLinks: false) !=
          FileSystemEntityType.directory) {
        throw FileSystemException(
            'Storage ancestor is not a directory', current);
      }
      final status = posix.lstat(current);
      final writeByOthers = (status.mode.mode & 0x12) != 0;
      // A sticky shared parent (normally /tmp) protects a service-owned
      // child from other users. The parent owner is part of trusted storage
      // configuration and must not be an attacker.
      final safeSticky = status.mode.isSticky;
      if (writeByOthers && !safeSticky) {
        throw FileSystemException(
            'Storage ancestor is writable by others', current);
      }
      final parent = p.dirname(current);
      if (parent == current) return;
      current = parent;
    }
  }

  void _secureOwnedDirectory(String path) {
    if (FileSystemEntity.typeSync(path, followLinks: false) !=
        FileSystemEntityType.directory) {
      throw FileSystemException(
          'Certificate directory is not a directory', path);
    }
    final status = posix.lstat(path);
    if (status.uid != _owner) {
      throw FileSystemException(
          'Certificate directory has a different owner', path);
    }
    if ((status.mode.mode & 0x1ff) != 0x1c0) {
      posix.chmod(path, '700');
    }
    final secured = posix.lstat(path);
    if (secured.uid != _owner ||
        !secured.mode.isDirectory ||
        (secured.mode.mode & 0x1ff) != 0x1c0) {
      throw FileSystemException(
          'Certificate directory is not owner-only', path);
    }
  }

  void _mkdirPrivate(String path) {
    final cPath = path.toNativeUtf8();
    try {
      final mkdir = ffi.DynamicLibrary.process().lookupFunction<
          ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Uint32),
          int Function(ffi.Pointer<Utf8>, int)>('mkdir');
      if (mkdir(cPath, 0x1c0) != 0) {
        throw FileSystemException(
            'Cannot create private certificate directory', path);
      }
    } finally {
      calloc.free(cPath);
    }
  }

  void _preparePrivateParent(Directory parent) {
    final parentPath = p.normalize(parent.absolute.path);
    if (parentPath == _rootPath || p.isWithin(_rootPath, parentPath)) {
      _prepareRoot();
      var current = _rootPath;
      final relative = p.relative(parentPath, from: _rootPath);
      if (relative == '.') return;
      for (final component in p.split(relative)) {
        current = p.join(current, component);
        if (FileSystemEntity.typeSync(current, followLinks: false) ==
            FileSystemEntityType.notFound) {
          _mkdirPrivate(current);
        }
        _secureOwnedDirectory(current);
      }
    } else {
      // A configured external key location is trusted configuration, but its
      // parent must already be owner-only. Never chmod an unrelated directory.
      _verifyTrustedAncestors(parentPath);
      final status = posix.lstat(parentPath);
      if (status.uid != _owner ||
          !status.mode.isDirectory ||
          (status.mode.mode & 0x1ff) != 0x1c0) {
        throw FileSystemException(
            'External private-key directory must be owner-only', parentPath);
      }
    }
  }

  void prepareKeyParent(Directory parent) => _preparePrivateParent(parent);

  /// Tightens an existing private key before it is returned or passed to TLS.
  /// Missing keys remain missing; this method never creates one.
  void secureExistingKey(File file) {
    final type = FileSystemEntity.typeSync(file.path, followLinks: false);
    if (type == FileSystemEntityType.notFound) return;
    _preparePrivateParent(file.parent);
    if (type != FileSystemEntityType.file) {
      throw FileSystemException('Private key is not a regular file', file.path);
    }
    final status = posix.lstat(file.path);
    if (!status.mode.isFile || status.uid != _owner || status.nlink != 1) {
      throw FileSystemException(
          'Private key has unsafe owner, type or link count', file.path);
    }
    if ((status.mode.mode & 0x1ff) != 0x180) {
      posix.chmod(file.path, '600');
    }
    final secured = posix.lstat(file.path);
    if (!secured.mode.isFile ||
        secured.uid != _owner ||
        secured.nlink != 1 ||
        (secured.mode.mode & 0x1ff) != 0x180) {
      throw FileSystemException('Private key is not owner-only', file.path);
    }
  }

  void writeKey(File target, String pem) {
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
