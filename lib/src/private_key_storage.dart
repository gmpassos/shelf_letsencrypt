import 'dart:io';
import 'dart:math';

import 'package:path/path.dart' as p;

import 'posix_stub.dart' if (dart.library.ffi) 'posix_ffi.dart';

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
  PrivateKeyStorage(Directory root, {this.readOnly = false})
      : _posix = Posix.current() {
    final path = p.normalize(root.absolute.path);
    if (_posix == null) {
      if (readOnly && !Directory(path).existsSync()) {
        changes.add('Create $path');
        _rootPath = path;
        return;
      }
      Directory(path).createSync(recursive: true);
      _rootPath = p.normalize(Directory(path).resolveSymbolicLinksSync());
    } else {
      _rootPath = _prepareRoot(path);
    }
  }

  final Posix? _posix;

  /// With [readOnly], the same checks run and throw, but nothing is created,
  /// written or changed: the changes that would be made are recorded in
  /// [changes] instead, and writing a key throws [StateError].
  final bool readOnly;

  /// The changes skipped in [readOnly] mode, in the order they were found.
  final Set<String> changes = {};

  void _checkWritable() {
    if (readOnly) throw StateError('Certificate storage is read-only');
  }

  /// The storage root with symbolic links resolved. Permission checks and file
  /// operations both use this path.
  late final String _rootPath;

  Directory get root => Directory(_rootPath);

  /// Creates or secures the root at [path] and returns its resolved path.
  /// With [expected], fails before creating anything if [path] would resolve
  /// elsewhere.
  String _prepareRoot(String path, {String? expected}) {
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
    if (expected != null &&
        p.joinAll([current, ...missing.reversed]) != expected) {
      throw FileSystemException('Storage root has moved', expected);
    }
    if (readOnly && missing.isNotEmpty) {
      final created = p.joinAll([current, ...missing.reversed]);
      changes.add('Create $created (0700)');
      return created;
    }
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
      _prepareRoot(_rootPath, expected: _rootPath);
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
      if (readOnly) {
        changes.add('Set $path to 0700');
        return;
      }
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
    if (_isManaged(parentPath)) {
      _secureRoot();
      var current = _rootPath;
      final relative = p.relative(parentPath, from: _rootPath);
      if (relative == '.') return;
      for (final component in p.split(relative)) {
        current = p.join(current, component);
        if (FileSystemEntity.typeSync(current, followLinks: false) ==
            FileSystemEntityType.notFound) {
          if (readOnly) {
            changes.add('Create $current (0700)');
            return;
          }
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
    _checkWritable();
    if (_posix == null) {
      parent.createSync(recursive: true);
    } else {
      _preparePrivateParent(parent);
    }
  }

  /// Prepares a parent for public keys or certificate chains. Managed paths
  /// cannot pass through a link left in an older certificate store. Configured
  /// external paths remain the operator's responsibility and retain their
  /// existing creation and permission behavior.
  /// Returns whether [parent] is managed, i.e. the root or inside it.
  bool _preparePublicParent(Directory parent) {
    _checkWritable();
    final parentPath = p.normalize(parent.absolute.path);
    if (!_isManaged(parentPath)) {
      parent.createSync(recursive: true);
      return false;
    }

    if (_posix == null) {
      if (FileSystemEntity.typeSync(_rootPath, followLinks: false) ==
          FileSystemEntityType.notFound) {
        Directory(_rootPath).createSync(recursive: true);
      }
      if (FileSystemEntity.typeSync(_rootPath, followLinks: false) !=
          FileSystemEntityType.directory) {
        throw FileSystemException('Storage root is not a directory', _rootPath);
      }
    } else {
      _secureRoot();
    }

    var current = _rootPath;
    final relative = p.relative(parentPath, from: _rootPath);
    if (relative == '.') return true;
    for (final component in p.split(relative)) {
      current = p.join(current, component);
      final type = FileSystemEntity.typeSync(current, followLinks: false);
      if (type == FileSystemEntityType.notFound) {
        if (_posix == null) {
          Directory(current).createSync();
        } else {
          _posix.mkdir(current, _ownerOnlyDirectory);
        }
      } else if (type != FileSystemEntityType.directory) {
        throw FileSystemException(
            'Certificate parent is not a directory', current);
      }
      if (_posix != null) {
        final status = _posix.lstat(current);
        if (!status.isDirectory || status.uid != _posix.euid) {
          throw FileSystemException(
              'Certificate parent has an unsafe owner or type', current);
        }
      }
    }
    return true;
  }

  /// Prepares the parent of a public key or certificate chain and checks that
  /// [target] is absent or a regular file. Returns whether [target] is managed.
  bool preparePublicTarget(File target, String description) {
    final managed = _preparePublicParent(target.parent);
    final type = FileSystemEntity.typeSync(target.path, followLinks: false);
    if (type != FileSystemEntityType.notFound &&
        type != FileSystemEntityType.file) {
      throw FileSystemException(
          '$description destination is not a regular file', target.path);
    }
    return managed;
  }

  bool _isManaged(String path) =>
      path == _rootPath || p.isWithin(_rootPath, path);

  /// Writes a public key or certificate chain. Inside the storage root the
  /// content is staged and renamed over [target], so a hard link left in an
  /// older store is replaced rather than written through. Configured external
  /// paths are written in place and keep their existing permissions.
  void writePublic(File target, String content, String description) {
    if (!preparePublicTarget(target, description)) {
      target.writeAsStringSync(content);
      return;
    }
    final random = Random.secure();
    final staging = File(p.join(target.parent.path,
        '.${p.basename(target.path)}.${random.nextInt(1 << 32)}.tmp'));
    staging.createSync(exclusive: true);
    try {
      staging.writeAsStringSync(content, flush: true);
      staging.renameSync(target.path);
    } finally {
      if (staging.existsSync()) staging.deleteSync();
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
      if (readOnly) {
        changes.add('Set ${file.path} to 0600');
        return;
      }
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
    _checkWritable();
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
