import 'dart:io';

import 'package:shelf_letsencrypt/src/cli/cli.dart';

Future<void> main(List<String> args) async {
  final code = await ShelfLetsEncryptCli().run(args);
  await Future.wait([stdout.flush(), stderr.flush()]);
  exit(code);
}
