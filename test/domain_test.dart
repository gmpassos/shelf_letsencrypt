import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';
import 'package:shelf_letsencrypt/src/logging.dart';
import 'package:test/test.dart';

void main() {
  group('Domain', () {
    const a = Domain(name: 'a.example.com', email: 'admin@a.example.com');
    const b = Domain(name: 'b.example.com', email: 'admin@b.example.com');

    test('fromDomainsNamesAndEmailsArgs', () {
      final domains = Domain.fromDomainsNamesAndEmailsArgs(
          'a.example.com, b.example.com',
          'admin@a.example.com;admin@b.example.com');

      expect(domains.map((d) => '$d'), equals(['$a', '$b']));
      expect(
          Domain.fromDomainsNamesAndEmailsArgs('a.example.com|b.example.com',
                  'admin@a.example.com|admin@b.example.com',
                  delimiter: RegExp(r'\|'))
              .map((d) => d.name),
          equals([a.name, b.name]));
    });

    test('fromDomainsNamesAndEmails requires one e-mail per domain', () {
      expect(
          () => Domain.fromDomainsNamesAndEmails(
              ['a.example.com', 'b.example.com'], ['admin@example.com']),
          throwsArgumentError);
    });

    test('list helpers', () {
      expect(Domain.toNames([a, b]), equals('a.example.com, b.example.com'));
      expect(Domain.asStrings([a, b]), equals([a.name, b.name]));
      expect(Domain.contains([a, b], 'b.example.com'), isTrue);
      expect(Domain.contains([a], 'b.example.com'), isFalse);
      expect('$a', equals('a.example.com: admin@a.example.com'));
    });
  });

  test('CheckCertificateStatus', () {
    expect(CheckCertificateStatus.ok.isOK, isTrue);
    expect(CheckCertificateStatus.okRefreshed.isOK, isTrue);
    expect(CheckCertificateStatus.okRefreshed.isOkRefreshed, isTrue);
    expect(CheckCertificateStatus.ok.isOkRefreshed, isFalse);
    expect(CheckCertificateStatus.invalid.isNotOK, isTrue);
    expect(CheckCertificateStatus.error.isNotOK, isTrue);
  });

  group('Logger', () {
    test('forwards to a custom Logging function', () {
      final logs = <(String, Object?, Object?, StackTrace?)>[];
      final logger = Logger((level, message, error, stackTrace) =>
          logs.add((level, message, error, stackTrace)));
      final stackTrace = StackTrace.current;

      logger.info('info');
      logger.warning('warning', 'cause');
      logger.error('error', 'cause', stackTrace);
      // An error and its stack trace, without a message:
      logger.error(StateError('failure'), stackTrace);
      // A message and a stack trace:
      logger.error('message', stackTrace);
      // Nothing to log:
      logger.info(null);

      expect(logs.map((e) => e.$1),
          equals(['INFO', 'WARNING', 'ERROR', 'ERROR', 'ERROR']));
      expect(logs[1].$3, equals('cause'));
      expect(logs[3].$2, isNull);
      expect(logs[3].$3, isA<StateError>());
      expect(logs[3].$4, same(stackTrace));
      expect(logs[4].$2, equals('message'));
      expect(logs[4].$3, isNull);
    });

    test('prints to the console by default', () {
      final printed = <Object?>[];
      final logger = _CapturingLogger(printed);

      logger.info('info');
      logger.error('error', 'cause', StackTrace.empty);
      logger.error(StateError('failure'), StackTrace.empty);

      expect(printed.whereType<String>(),
          contains(contains('[INFO]    LetsEncrypt > info')));
      expect(printed, contains('[ERROR] cause'));
      expect(printed.whereType<String>(),
          contains(contains('LetsEncrypt > Bad state: failure')));
      expect(printed, contains(StackTrace.empty));
    });
  });
}

class _CapturingLogger extends Logger {
  _CapturingLogger(this.printed) : super(null);

  final List<Object?> printed;

  @override
  void printToConsole(Object? o) => printed.add(o);
}
