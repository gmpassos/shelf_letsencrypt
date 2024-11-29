typedef Logging = void Function(
    String level, Object? message, Object? error, StackTrace? stackTrace);

class Logger {
  Logging? log;

  Logger(this.log);

  void info(Object? m, [StackTrace? stackTrace]) {
    _logImpl('INFO', m, null, stackTrace);
  }

  void warning(Object? m, [Object? error, StackTrace? stackTrace]) {
    _logImpl('WARNING', m, error, stackTrace);
  }

  void error(Object? m, [Object? error, StackTrace? stackTrace]) {
    if (error != null && stackTrace == null && error is StackTrace) {
      stackTrace = error;
      if (m is! String) {
        error = m;
        m = null;
      } else {
        error = null;
      }
    }

    _logImpl('ERROR', m, error, stackTrace);
  }

  void _logImpl(
      String level, Object? m, Object? error, StackTrace? stackTrace) {
    if (m == null && error == null && stackTrace == null) {
      return;
    }

    final log = this.log;
    if (log != null) {
      log(level, m, error, stackTrace);
    } else {
      final now = DateTime.now();

      final time = '$now'.padRight(26, '0');

      final levelName = '[$level]'.padRight(9);

      if (m == null && error != null) {
        m = error;
        error = null;
      }

      if (m != null) {
        final message = '$time $levelName LetsEncrypt > $m';
        printToConsole(message);
      }

      if (error != null) {
        printToConsole('[ERROR] $error');
      }

      if (stackTrace != null) {
        printToConsole(stackTrace);
      }
    }
  }

  void printToConsole(Object? o) {
    // ignore: avoid_print
    print(o);
  }
}
