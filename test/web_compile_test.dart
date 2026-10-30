import 'dart:io';

import 'package:path/path.dart' as pack_path;
import 'package:test/test.dart';

void main() {
  late Directory tmpDir;

  setUp(() => tmpDir = Directory.systemTemp.createTempSync('shelf-le-web-'));

  tearDown(() => tmpDir.deleteSync(recursive: true));

  // Packages importing the library from code also compiled for the web (like
  // `bones_api`) must still compile: no unconditional `dart:ffi` import.
  test('the library compiles with dart2js', () {
    final main = File(pack_path.join(tmpDir.path, 'main.dart'))
      ..writeAsStringSync(
          "import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';\n"
          'void main() => print(LetsEncrypt);\n');

    final result = Process.runSync(Platform.resolvedExecutable, [
      'compile',
      'js',
      '--packages=${pack_path.absolute('.dart_tool', 'package_config.json')}',
      '-o',
      pack_path.join(tmpDir.path, 'main.js'),
      main.path,
    ]);

    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
