/// The fields of a file status used by `PrivateKeyStorage`.
final class PosixStat {
  const PosixStat({required this.mode, required this.nlink, required this.uid});

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
