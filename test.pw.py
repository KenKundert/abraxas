#!/bin/env python

# Test PW
# Imports {{{1
from runtests import cmdLineOpts, writeSummary
from textcolors import Colors
from pw import Password, PasswordError
from fileutils import remove
from textwrap import dedent
import sys
import os

# Initialization {{{1
fast, printSummary, printTests, printResults, colorize, parent = cmdLineOpts()
testsRun = 0
failures = 0
remove('./generated_settings')

colors = Colors(colorize)
succeed = colors.colorizer('green')
fail = colors.colorizer('red')
info = colors.colorizer('magenta')
status = colors.colorizer('cyan')

# Case class {{{2
class Case():
    def __init__(self, **kwargs):
        self.__dict__ = kwargs

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, ', '.join(
            ['%s=%s' % item for item in self.__dict__.items()]
        ))
    __repr__ = __str__

    def __getattr__(self, name):
        return None

# Utilities {{{1
def create_bogus_file(filename):
    with open(filename, 'w') as f:
        f.write("bogus = 0")

# Test cases {{{1
testCases = [
    # Run Password with a bogus settings directory
    Case(stimulus="pw = Password('/dev/null')",
        expected="/dev/null/master.gpg: Not a directory.",
        expectError=True,
        isCommand=True),

    # Run Password with damaged accounts file
    Case(stimulus="pw = Password('./generated_settings', '4DC3AD14', None, 'test_key')"),
    Case(stimulus="create_bogus_file('./generated_settings/accounts')"),
    Case(stimulus="pw = Password('./generated_settings', gpg_home='test_key')"),
    Case(
        stimulus="pw.read_accounts()",
        expected=dedent("generated_settings/accounts: defective accounts file, 'accounts' not found."),
        expectError=True),
    Case(stimulus="remove('./generated_settings')"),

    # Run Password with damaged master password file
    Case(stimulus="pw = Password('./generated_settings', '4DC3AD14', None, 'test_key')"),
    Case(stimulus="create_bogus_file('./generated_settings/master.asc')"),
    Case(stimulus="pw = Password('./generated_settings', gpg_home='test_key')",
        expected=dedent("""\
            generated_settings/master.gpg: unable to decrypt.
            gpg: no valid OpenPGP data found.
            [GNUPG:] NODATA 1
            [GNUPG:] NODATA 2
            gpg: decrypt_message failed: eof
        """),
        expectError=True,
        isCommand=True),
    Case(stimulus="remove('./generated_settings')"),

    # Run Password with a nonexistant settings directory
    Case(stimulus="pw = Password('./generated_settings', '4DC3AD14', None, 'test_key')"),
    Case(stimulus="pw.read_accounts()"),
    Case(
        stimulus="' '.join(sorted(pw.all_templates()))",
        expected='=anum =chars =extreme =master =num =words'),
    Case(stimulus="account = pw.get_account('test')"),
    Case(
        stimulus="account.get_id()",
        expected='test'),
    Case(
        stimulus="pw.generate_password()",
        expected='postdate sprayer payment aircrew'),
    Case(stimulus="account = pw.get_account('=chars')"),
    Case(
        stimulus="pw.generate_password()",
        expected='HhqaECyF=]nt'),
    Case(stimulus="account = pw.get_account('=words')"),
    Case(
        stimulus="pw.generate_password()",
        expected='placate embody tinker razor'),
    Case(stimulus="account = pw.get_account('=master')"),
    Case(
        stimulus="pw.generate_password()",
        expected='conflate orifice posting blind rookie earmark mediator impulse'),
    Case(stimulus="account = pw.get_account('=extreme')"),
    Case(
        stimulus="pw.generate_password()",
        expected='''R}-|v6IL9OQIp)U07t1OQ$jz"1qX$VLOqkSac!|b&mlc:rlD|fhKO|(O9%&oI#]J'''),
    Case(stimulus="pw.get_account('fuzzbucket')"),
    Case(
        stimulus="pw.generate_password()",
        expected="llama libretto stump analgesic"),
    Case(
        stimulus="pw.print_changed_secrets()",
        expected="generated_settings/archive.gpg: No such file or directory.",
        expectError=True),
    Case(stimulus="pw.archive_secrets()"),
    Case(stimulus="pw.print_changed_secrets()"),

    # Run Password with the test settings directory
    Case(stimulus="os.system('rm -f test_settings/master.gpg')"),
    Case(stimulus="os.system('gpg --homedir test_key -r 4DC3AD14 -e test_settings/master')"),
    Case(stimulus="pw = Password('./test_settings', gpg_home='test_key')"),
    Case(stimulus="pw.read_accounts()"),
    Case(
        stimulus="';'.join(['%s(%s)' % (each[0], ','.join(each[1])) for each in sorted(pw.find_accounts('col'), key=lambda x: x[0])])",
        expected='colgate(Colgate,Cg)',
    ),
    Case(
        stimulus="';'.join(['%s(%s)' % (each[0], ','.join(each[1])) for each in sorted(pw.search_accounts('smiler'), key=lambda x: x[0])])",
        expected='crest(Crest);sensodyne()',
    ),
    Case(
        stimulus="' '.join(sorted(pw.all_accounts()))",
        expected='colgate crest sensodyne toms'),
    Case(
        stimulus="';'.join(['%s(%s)' % (each[0], ','.join(each[1])) for each in sorted(pw.find_accounts('e'), key=lambda x: x[0])])",
        expected='colgate(Colgate,Cg);crest(Crest);sensodyne()'),
    Case(stimulus="account = pw.get_account('crest')"),
    Case(
        stimulus="account.get_id()",
        expected='crest'),
    Case(
        stimulus="pw.generate_password()",
        expected='crewman ledge cranny prelate'),
    Case(
        stimulus="account.get_field('username')",
        expected='smiler'),
    Case(
        stimulus="account.get_field('account')",
        expected='1234-5678'),
    Case(
        stimulus="account.get_field('email')",
        expected='smiler@nowhere.com'),
    Case(
        stimulus="account.get_field('url')",
        expected='www.crest.com'),
    Case(
        stimulus="account.get_field('remarks')",
        expected='Remarks about crest'),
    Case(
        stimulus="' '.join(pw.generate_answer(0))",
        expected='How many teeth do you have? specify cutter sense batten'),
    Case(
        stimulus="' '.join(pw.generate_answer(1))",
        expected='How many teeth are missing? animal siege bootee entertain'),
    Case(stimulus="account = pw.get_account('colgate')"),
    Case(
        stimulus="account.get_id()",
        expected='colgate'),
    Case(
        stimulus="pw.generate_password()",
        expected='toothpaste'),
    Case(stimulus="account = pw.get_account('sensodyne')"),
    Case(
        stimulus="account.get_id()",
        expected='sensodyne'),
    Case(
        stimulus="pw.generate_password()",
        expected='pre:c8c00e9ec19e:suf'),
    Case(stimulus="account = pw.get_account('toms')"),
    Case(
        stimulus="account.get_id()",
        expected='toms'),
    Case(
        stimulus="pw.generate_password()",
        expected='tP,)olY+lA~Qt>4/APS4{C+drq$]Edg.Gs"d2]YEGnL>cP-5IYKEs_WXso*L{U z'),
    Case(stimulus="account = pw.get_account('none')"),
    Case(
        stimulus="account.get_id()",
        expected='none'),
    Case(
        stimulus="pw.generate_password()",
        expected='opening herbalist ointment migrate'),
    Case(
        stimulus="pw.generate_answer(5)",
        expected="There is no security question #5.",
        expectError=True),
]

# Run tests {{{1
for index, case in enumerate(testCases):
    testsRun += 1
    stimulus = case.stimulus
    expected = case.expected
    expectError = case.expectError
    isCommand = case.isCommand
    if expectError:
        assert(expected)

    if printTests:
        print(status('Trying %d:' % index), stimulus)

    # If expected is not provided, then this is not a test. Rather, it is a
    # function that must be called before the remaining tests can be run.
    if isCommand or not expected:
        try:
            exec(stimulus)
        except PasswordError as err:
            if not expectError or expected != err.message:
                sys.exit(
                    "Error found when executing '%s': %s" % (stimulus, err.message))
        continue

    try:
        result = eval(stimulus)
        failure = (result != expected)
        if failure:
            failures += 1
            print(fail('Failure detected (%s):' % failures))
            print(info('    Given:'), stimulus)
            print(info('    Result  :'), result)
            print(info('    Expected:'), expected)
        elif expectError:
            failures += 1
            print(fail('Expected error not detected (%s):' % failures))
            print(info('    Result  :'), result)
            print(info('    Expected:'), expected)
        elif printResults:
            print(succeed('    Result:'), result)
    except PasswordError as err:
        if not expectError or err.message != expected:
            failures += 1
            print(fail('Unexpected error detected (%s):' % failures))
            print(info('    Given:'), stimulus)
            print(info('    Result  :'), err.message)
            print(info('    Expected:'), expected)

        elif printResults:
            print(succeed('    Expected error detected:'), err.message)

# Print test summary {{{1
numTests = len(testCases)
assert testsRun == numTests, "%s of %s tests run" % (testsRun, numTests)
if printSummary:
    print('%s: %s tests run, %s failures detected.' % (
        fail('FAIL') if failures else succeed('PASS'), testsRun, failures
    ))

writeSummary(testsRun, failures)
sys.exit(int(bool(failures)))
