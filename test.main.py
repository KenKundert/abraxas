#!/usr/bin/env python

# Test the Password Generator

# Imports (fold)
from __future__ import print_function, division
from runtests import (
    cmdLineOpts, writeSummary, succeed, fail, info, status, warning
)
from abraxas import PasswordGenerator, PasswordError, Logging
from abraxas.prefs import GPG_BINARY
from fileutils import remove
from textwrap import dedent
import sys
import os

# Initialization (fold)
fast, printSummary, printTests, printResults, colorize, parent = cmdLineOpts()
testsRun = 0
failures = 0
remove('./generated_settings')
os.chmod("test_key", 0o700)

class Case():
    CONTEXT = {}
    OUTPUT = []
    NAMES = set()

    def __init__(self, name, stimulus,
        result=None, output=None, error=None, clean=False
    ):
        self.stimulus = stimulus       # python code to evaluate
        self.name = name               # name of test case, arbitrary but should be unique
        assert name not in Case.NAMES
        Case.NAMES.add(name)
        self.expected_result = result  # expected result from evaluating the stimulus
        self.expected_output = output.strip().split('\n') if output else []
                                       # expected output messages
        self.expected_error = error    # expected error message
        self.context = Case.CONTEXT
        if clean:
            self.context.clear()
        self.context['logger'] = Logging(
            output_callback=lambda msg: self.set_output(msg),
            exception=PasswordError)
        self.context['self'] = self

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, ', '.join(
            ['%s=%s' % item for item in self.__dict__.items()]
        ))
    __repr__ = __str__

    def __getattr__(self, name):
        return None

    def is_test(self):
        return self.expected_error or self.expected_result or self.expected_output

    def run(self):
        del Case.OUTPUT[:]
        self.error = None
        self.passes = None
        self.result = None
        try:
            if self.expected_result:
                self.result = eval(self.stimulus, globals(), self.context)
            else:
                exec(self.stimulus, globals(), self.context)
        except PasswordError as err:
            self.error = str(err)
        except (SyntaxError, NameError, KeyError, AttributeError) as err:
            print("Error found with stimulus: <%s>" % self.stimulus)
            raise
        except:
            return (self.name, self.stimulus, None, None, 'exception')

        self.output = Case.OUTPUT[:]
        if self.error != self.expected_error:
            return (self.name, self.stimulus, self.error, self.expected_error, 'error')
        if self.result != self.expected_result:
            return (self.name, self.stimulus, self.result, self.expected_result, 'result')
        if self.output != self.expected_output:
            return (self.name, self.stimulus, self.output, self.expected_output, 'output')
        return None

    def set_output(self, message):
        Case.OUTPUT += message.split('\n')


# Stop class {{{1
class Exit(Case):
    def __init__(self):
        pass

    def run(self):
        sys.exit('TERMINATING TESTS UPON DEVELOPER REQUEST')

# Utilities {{{1
def create_bogus_file(filename):
    with open(filename, 'w') as f:
        f.write("bogus = 0")

# Test cases {{{1
testCases = [
    # Run Password with a bogus settings directory
    Case(
        name='endeavor',
        stimulus="pw = PasswordGenerator('/dev/null', logger=logger)",
        output="Warning: could not read master password file /dev/null/master.gpg: Not a directory.",
        clean=True
    ),

    # Run PasswordGenerator with damaged accounts file
    Case(
        name='stagnate',
        stimulus="os.system('rm -rf generated_settings')"
    ),
    Case(
        name='ascent',
        stimulus="pw = PasswordGenerator('./generated_settings', '4DC3AD14', logger, 'test_key')",
        output=dedent('''
            generated_settings/master.gpg: created.
            generated_settings/accounts: created.
        '''),
        clean=True
    ),
    Case(
        name='quiche',
        stimulus="create_bogus_file('./generated_settings/accounts')"
    ),
    Case(
        name='mover',
        stimulus="pw = PasswordGenerator('./generated_settings', logger=logger, gpg_home='test_key')",
        clean=True
    ),
    Case(
        name='doorbell',
        stimulus="pw.read_accounts()",
        error="generated_settings/accounts: defective accounts file, 'accounts' not found."
    ),
    Case(
        name='compile',
        stimulus="remove('./generated_settings')"
    ),

    # Run PasswordGenerator with damaged master password file
    Case(
        name='debut',
        stimulus="os.system('rm -rf generated_settings')"
    ),
    Case(
        name='octagon',
        stimulus="pw = PasswordGenerator('./generated_settings', '4DC3AD14', logger, 'test_key')",
        clean=True,
        output=dedent('''
            generated_settings/master.gpg: created.
            generated_settings/accounts: created.
        ''')),
    Case(
        name='entertain',
        stimulus="create_bogus_file('./generated_settings/master.gpg')"
    ),
    Case(
        name='stabbing',
        stimulus="pw = PasswordGenerator('./generated_settings', logger=logger, gpg_home='test_key')",
        error=dedent("generated_settings/master.gpg: unable to decrypt.")
    ),
    Case(
        name='secretary',
        stimulus="remove('./generated_settings')"
    ),

    # Run PasswordGenerator with a nonexistant settings directory
    Case(
        name='albino',
        stimulus="os.system('rm -rf generated_settings')"
    ),
    Case(
        name='crone',
        stimulus="pw = PasswordGenerator('./generated_settings', '4DC3AD14', logger, 'test_key')",
        output=dedent("""
            generated_settings/master.gpg: created.
            generated_settings/accounts: created.
        """),
    ),
    Case(
        name='airlock',
        stimulus="pw.read_accounts()"
    ),
    Case(
        name='pastiche',
        stimulus="' '.join(sorted(pw.all_templates()))",
        result='=anum =chars =extreme =master =num =pin =word =words'
    ),
    Case(
        name='corrode',
        stimulus="account = pw.get_account('test')",
        output="Warning: account 'test' not found.",
    ),
    Case(
        name='whine',
        stimulus="account.get_id()",
        result='test'
    ),
    Case(
        name='janitor',
        stimulus="pw.generate_password()",
        result='stiffen centaur partition umbrella'
    ),
    Case(
        name='picture',
        stimulus="account = pw.get_account('=chars')"
    ),
    Case(
        name='narrator',
        stimulus="pw.generate_password()",
        result='O%|wAkx2JB|S'
    ),
    Case(
        name='bagatelle',
        stimulus="account = pw.get_account('=words')"
    ),
    Case(
        name='spellbind',
        stimulus="pw.generate_password()",
        result='measure bulky opiate cowman'
    ),
    Case(
        name='poplar',
        stimulus="account = pw.get_account('=master')"
    ),
    Case(
        name='scrimmage',
        stimulus="pw.generate_password()",
        result='quilt latchkey pedicure fuzzy collate deflate trowel victim'
    ),
    Case(
        name='forswear',
        stimulus="account = pw.get_account('=extreme')"
    ),
    Case(
        name='rhesus',
        stimulus="pw.generate_password()",
        result='''|cBZN|ha{#7#R?zb#Z8WG.P1.9Uag5C[0S4C$6[wmhL!$u!Y^b(["7m6`no[fWub'''
    ),
    Case(
        name='practical',
        stimulus="pw.get_account('fuzzbucket')",
        output="Warning: account 'fuzzbucket' not found.",
    ),
    Case(
        name='booth',
        stimulus="pw.generate_password()",
        result="solution meaty scatter ambition"
    ),
    Case(
        name='impeach',
        stimulus="pw.print_changed_secrets()",
        error="generated_settings/archive.gpg: No such file or directory."
    ),
    Case(
        name='daylight',
        stimulus="pw.archive_secrets()"
    ),
    Case(
        name='cattleman',
        stimulus="pw.print_changed_secrets()"
    ),

    # Run PasswordGenerator with the test settings directory
    Case(
        name='marsh',
        stimulus="os.system('rm -f test_settings/master.gpg')"
    ),
    Case(
        name='peasant',
        stimulus="os.system('%s --homedir test_key -r 4DC3AD14 -e test_settings/master')" % GPG_BINARY
    ),
    Case(
        name='digestion',
        stimulus="os.system('rm -f test_settings/master2.gpg')"
    ),
    Case(
        name='holocaust',
        stimulus="os.system('%s --homedir test_key -r 4DC3AD14 -e test_settings/master2')" % GPG_BINARY
    ),
    Case(
        name='torch',
        stimulus="pw = PasswordGenerator('./test_settings', logger=logger, gpg_home='test_key')"
    ),
    Case(
        name='crosswind',
        stimulus="pw.read_accounts()"
    ),
    Case(
        name='tablet',
        stimulus="';'.join(['%s(%s)' % (each[0], ','.join(each[1])) for each in sorted(pw.find_accounts('col'), key=lambda x: x[0])])",
        result='colgate(Colgate,Cg)',
    ),
    Case(
        name='restorer',
        stimulus="';'.join(['%s(%s)' % (each[0], ','.join(each[1])) for each in sorted(pw.search_accounts('smiler'), key=lambda x: x[0])])",
        result='crest(Crest);sensodyne()',
    ),
    Case(
        name='cosset',
        stimulus="' '.join(sorted(pw.all_accounts()))",
        result='aquafresh colgate crest sensodyne toms'
    ),
    Case(
        name='clapboard',
        stimulus="';'.join(['%s(%s)' % (each[0], ','.join(each[1])) for each in sorted(pw.find_accounts('e'), key=lambda x: x[0])])",
        result='aquafresh();colgate(Colgate,Cg);crest(Crest);sensodyne()'
    ),
    Case(
        name='meaning',
        stimulus="account = pw.get_account('crest')"
    ),
    Case(
        name='regency',
        stimulus="account.get_id()",
        result='crest'
    ),
    Case(
        name='summons',
        stimulus="pw.generate_password()",
        result='crewman ledge cranny prelate'
    ),
    Case(
        name='cougar',
        stimulus="account.get_field('username')",
        result='smiler'
    ),
    Case(
        name='discover',
        stimulus="account.get_field('account')",
        result='1234-5678'
    ),
    Case(
        name='larder',
        stimulus="account.get_field('email')",
        result='smiler@nowhere.com'
    ),
    Case(
        name='amount',
        stimulus="account.get_field('url')",
        result='www.crest.com'
    ),
    Case(
        name='talkie',
        stimulus="account.get_field('remarks')",
        result='Remarks about crest'
    ),
    Case(
        name='venue',
        stimulus="' '.join(pw.generate_answer(0))",
        result='How many teeth do you have? specify cutter sense batten'
    ),
    Case(
        name='agnostic',
        stimulus="' '.join(pw.generate_answer(1))",
        result='How many teeth are missing? animal siege bootee entertain'
    ),
    Case(
        name='footplate',
        stimulus="account = pw.get_account('colgate')"
    ),
    Case(
        name='outstay',
        stimulus="account.get_id()",
        result='colgate'
    ),
    Case(
        name='scoundrel',
        stimulus="pw.generate_password()",
        result='white teeth'
    ),
    Case(
        name='fleshy',
        stimulus="account = pw.get_account('sensodyne')"
    ),
    Case(
        name='valance',
        stimulus="account.get_id()",
        result='sensodyne'
    ),
    Case(
        name='decision',
        stimulus="pw.generate_password()",
        result='pre:c8c00e9ec19e:suf'
    ),
    Case(
        name='suspend',
        stimulus="account = pw.get_account('toms')"
    ),
    Case(
        name='earphone',
        stimulus="account.get_id()",
        result='toms'
    ),
    Case(
        name='pride',
        stimulus="pw.generate_password()",
        result='tP,)olY+lA~Qt>4/APS4{C+drq$]Edg.Gs"d2]YEGnL>cP-5IYKEs_WXso*L{U z'
    ),
    Case(
        name='fathead',
        stimulus="account = pw.get_account('aquafresh')"
    ),
    Case(
        name='culprit',
        stimulus="account.get_id()",
        result='aquafresh'
    ),
    Case(
        name='labyrinth',
        stimulus="pw.generate_password()",
        result='toothpaste'
    ),
    Case(
        name='puree',
        stimulus="account = pw.get_account('none')",
        output="Warning: account 'none' not found."
    ),
    Case(
        name='billion',
        stimulus="account.get_id()",
        result='none'
    ),
    Case(
        name='frizzy',
        stimulus="pw.generate_password()",
        result='opening herbalist ointment migrate'
    ),
    Case(
        name='siesta',
        stimulus="pw.generate_answer(5)",
        error="There is no security question #5."
    ),

    # Run PasswordGenerator in stateless mode
    Case(
        name='vacillate',
        stimulus="pw = PasswordGenerator(stateless=True, logger=logger)"
    ),
    Case(
        name='lather',
        stimulus="pw.read_accounts(template=None)"
    ),
    Case(
        name='flashbulb',
        stimulus="account = pw.get_account('fuzzy')"
    ),
    Case(
        name='thump',
        stimulus="pw.generate_password(master_password='bottom')",
        result='charlatan routine stagy printout'
    ),
    Case(
        name='stiff',
        stimulus="pw = PasswordGenerator(stateless=True, logger=logger)"
    ),
    Case(
        name='lanyard',
        stimulus="pw.read_accounts(template='=anum')"
    ),
    Case(
        name='nibble',
        stimulus="account = pw.get_account('fuzzy')"
    ),
    Case(
        name='racialist',
        stimulus="pw.generate_password(master_password='bottom')",
        result='BwHWJgh3MPDh'
    ),
]

# Run tests {{{1
for case in testCases:

    testsRun += 1
    if printTests:
        print(status('Trying %d (%s):' % (testsRun, case.name)), case.stimulus)

    failure = case.run()

    if failure:
        failures += 1
        name, stimulus, result, expected, kind = failure
        print(fail('Unexpected %s (%s):' % (kind, failures)))
        print(info('    Case    :'), name)
        print(info('    Given   :'), stimulus)
        print(info('    Result  :'), result)
        print(info('    Expected:'), expected)

# Print test summary {{{1
numTests = 76
assert testsRun == numTests, "Incorrect number of tests run (%s of %s)." % (testsRun, numTests)
if printSummary:
    print('%s: %s tests run, %s failures detected.' % (
        fail('FAIL') if failures else succeed('PASS'), testsRun, failures
    ))

writeSummary(testsRun, failures)
sys.exit(int(bool(failures)))

# vim: set sw=4 sts=4 et:
