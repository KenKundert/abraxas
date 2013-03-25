#!/usr/bin/env python3
# Generates passwords and pass phrases based on stored account information.

# Imports {{{1
from fileutils import (
    makePath as make_path,
    getTail as get_tail,
    getHead as get_head,
    isFile as is_file,
    expandPath as expand_path,
    fileIsReadable as file_is_readable,
    mkdir, exists,
    execute, pipe, ExecuteError
)
import secrets
from textwrap import dedent, wrap, indent
from time import sleep
import argparse
import gnupg
import hashlib
import re
import os
import sys

# Globals {{{1
default_settings_dir = '~/.config/pw'
master_password_filename = 'master.gpg'
accounts_filename = 'accounts'
dictionary_filename = 'words'
default_template = "=words"
default_autotype = "{username}{tab}{password}{return}"
search_fields = ['username', 'account', 'email', 'url', 'remarks']
# Use absolute paths for xdotool and xsel so that nobody can replace them and
# see the secrets.
xdotool = '/usr/bin/xdotool'
xsel = '/usr/bin/xsel'
secrets_sha1 = "db7ce3fc4a9392187d0a8df7c80b0cdfd7b1bc22"

# Initial master password file {{{2
master_password_file_initial_contents = dedent('''\
    dict_hash = "%s" # DO NOT CHANGE THIS LINE
    secrets_hash = "%s" # DO NOT CHANGE THIS LINE

    passwords = {
        'default': """<%s>""", # DO NOT CHANGE THIS LINE
    }
    default_password = 'default'
    password_overrides = {
        '<account>': """<place password here>""",
    }
''')

# Initial accounts file {{{2
accounts_file_initial_contents = dedent('''\
    # Account information
    #
    # Add information about each of your accounts to the accounts dictionary.
    #
    # You can use the character sets and exclude function to create alphabets
    # for you character-base passwords. You can use the dedent function to strip
    # leading whitespace from multi-line remarks.

    from textwrap import dedent

    # Character sets
    # Use these to construct alphabets by summing together the ones you want.
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    letters = lowercase + uppercase
    digits = "0123456789"
    alphanumeric = letters + digits
    hexdigits = "0123456789abcdef"
    punctuation = """!"#$%%&'()*+,-./:;<=>?@[\]^_`{|}~"""
    whitespace = " \\t"
    printable = alphanumeric + punctuation + whitespace
    
    # Exclude function
    # Use this to strip characters from a character set.
    def exclude(chars, exclusions):
        return chars.translate(str.maketrans('', '', exclusions))

    # Example:
    # To create an alphabet with all characters except tabs use either:
    #     'alphabet': exclude(printable, '\\t')
    # or:   
    #     'alphabet': alphanumeric + punctuation + ' '

    # Give the desired location of the file
    logfile = '%s'
    
    # Account Information
    # Add your account information here ...
    accounts = {
        # Templates
        # The first view are intended to be templates.
        # Any account can be used as a template for another account.
        # Those that are designated as templates (ID starts with +) cannot be
        # used as an actual account and will not be listed in find and search
        # results. Feel free to modify, delete, or add your own templates.
        # You might want to choose short names with no spaces or glob characters
        # for those templates you plan to use from the command line.
        "=words": {  # typically used for linux pass phrases
            'password-type': 'words',
            'num-words': 4,
            'autotype': "{password}{return}",
        },
        "=chars": {  # typically used for web passwords
            'password-type': 'chars',
            'num-chars': 12,
            'alphabet': alphanumeric + punctuation,
            'autotype': "{username}{tab}{password}{return}",
        },
        "=master": {  # typically used to generate master passwords for pw
            'password-type': 'words',
            'num-words': 8,
        },
        "=extreme": {  # used in situations where there are no limits
            'password-type': 'chars',
            'num-chars': 64,
            'alphabet': exclude(printable, '\\t'),
        },

        # Accounts
        # Place your accounts here.
    #   "<account-id>": {
    #       'username': "<username>",
    #       'account': "<account-number>",
    #       'email': "<email>",
    #       'url': "<url>",
    #       'security questions': [
    #           "<question 0>",
    #           "<question 1>",
    #           ...
    #       ],
    #       'remarks': """<remarks>""",
    #       'version': "<version>",
    #       'window': [],       # a glob string or list of glob strings that
    #                           # are used to match window titles to this
    #                           # account
    #       'autotype': "{username}{tab}{password}{return}",
    #       'template': "<an account id>",
    #       'master': "<a master password id>",
    #       'password-type': 'words',    # choose between "words" and "chars"
    #       'num-chars': <int>, # used for pass phrases and security questions
    #       'num-words': <int>, # used for passwords
    #       'alphabet': alphanumeric # construct from character sets
    #       'prefix': '',
    #       'suffix': '',
    #   },
    }
''')

# Utilities {{{1
# Log a message (send it to the log file) {{{2
def log(message, logger):
    try:
        logger.log(message)
    except:
        pass

# Display a message {{{2
def display(message, logger):
    log(message, logger)
    print(message)

# Report an error {{{2
def error(message, logger):
    log(message, logger)
    raise PasswordError(message)

# Exit cleanly {{{2
def exit(logger):
    log('Terminates normally', logger)
    sys.exit()

# Command line class {{{1
class CommandLine:
    def __init__(self, argv):
        self.prog_name = get_tail(argv[0])
        cmd_line = argparse.ArgumentParser(add_help=False,
            description="Generate strong and unique password.")
        arguments = cmd_line.add_argument_group('Arguments')
        arguments.add_argument('account', nargs='?', default='',
            help="Generate password specific to this account.")
        options = cmd_line.add_argument_group('Options')
        options.add_argument('-p', '--password', action='store_true',
            help="Output the password (default if nothing else is requested).")
        options.add_argument('-n', '--username', action='store_true',
            help="Output the username.")
        options.add_argument('-a', '--account-number', action='store_true',
            help="Output the account number.")
        options.add_argument('-e', '--email', action='store_true',
            help="Output the email.")
        options.add_argument('-u', '--url', action='store_true',
            help="Output the URL.")
        options.add_argument('-q', '--question', type=int, metavar='<N>',
            default=None, help="Output security question N.")
        options.add_argument('-r', '--remarks', action='store_true',
            help="Output remarks.")
        options.add_argument('-A', '--all', action='store_true',
            help="Output everything.")
        group = cmd_line.add_mutually_exclusive_group()
        group.add_argument('-c', '--clipboard', action='store_true',
            help="Write output to clipboard rather than stdout.")
        group.add_argument('-t', '--autotype', action='store_true',
            help=(' '.join([
                "Mimic keyboard to send output to the active window rather than",
                "stdout. In this case any command line arguments that specify",
                "what to output are ignored and the autotype entry scripts",
                "the output."])))
        options.add_argument('-f', '--find', type=str, metavar='<str>',
            help="List any account that contains the given string in its ID.")
        options.add_argument('-s', '--search', type=str, metavar='<str>',
            help=(' '.join([
                "List any account that contains the given string in",
                "%s, or its ID." % ', '.join(search_fields)])))
        options.add_argument('-d', '--default-template',
            type=str, metavar='<template>', default=None,
            help="Template to use if account is not found.")
        options.add_argument('-l', '--list-templates', action='store_true',
            help=(' '.join([
                "List available templates (only pure templates are listed, not",
                "accounts, even though accounts can be used as templates)."])))
        options.add_argument('-w', '--wait', type=float, default=60, metavar='<secs>',
            help="Wait this long before clearing the secret (use 0 to disable).")
        options.add_argument('-i', '--init', type=str, metavar='<GPG ID>',
            help=(' '.join([
                "Initialize the master password and account files in",
                default_settings_dir,
                "(but only if they do not already exist)."])))
        options.add_argument('-h', '--help',  action='store_true',
            help="Show this help message and exit.")

        cmd_line_args = cmd_line.parse_args()

        # If requested, print help message and exit
        if cmd_line_args.help:
            cmd_line.print_help()
            sys.exit()

        # Save all the command line arguments as attributes of self
        self.__dict__.update(cmd_line_args.__dict__)

    def prog_name(self):
        return self.prog_name
# Logging class {{{1
# Log messages to a file
class Logging:
    def __init__(self, logfile = None, argv = None, prog_name = None):
        if logfile:
            self.logfile = self.set_logfile(logfile)
        else:
            self.logfile = None
        self.cache = []
        if argv:
            self.log('Invoked as: %s' % ' '.join(argv))
        self.prog_name = prog_name
        if argv and not prog_name:
            self.prog_name = argv[0]

    # Open the logfile.
    def set_logfile(self, logfile):
        try:
            self.logfile = open(expand_path(logfile), 'w')
        except IOError as err:
            self.display('%s: %s.' % (err.filename, err.strerror))

        # Now that logfile is open, write any messages that were cached
        self.log('\n'.join(self.cache))
        self.cache = []

    # Print the messages and also send it to the logfile.
    def display(self, msg):
        self.log(msg)
        print(msg)

    # Only send the message to the logfile.
    def log(self, msg):
        if msg:
            if self.logfile:
                self.logfile.write(msg + '\n')
            else:
                self.cache.append(msg)

    # Close the logfile.
    def _terminate(self):
        if self.logfile:
            self.logfile.close()

    # Support for the with statement
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self._terminate()

# Dictionary class {{{1
# The dictionary is a large list of words used to create pass phrases. It is
# contained in a file either in the settings or install directory.
class Dictionary():
    def __init__(self, filename, settings_dir, logger):
        path = self._find_dictionary(filename, settings_dir)
        self.path = path
        contents = self._read_dictionary(path)
        self.hash = hashlib.sha1(contents.encode('utf-8')).hexdigest()
        self.words = contents.split()
        self.logger = logger

    # Find dictionary {{{2
    # Finds the file that contains the dictionary of words used to construct
    # pass phrases. Initially looks in the settings directory, if not there look
    # in install directory.
    def _find_dictionary(self, filename, settings_dir):
        path = make_path(settings_dir, filename)
        if not exists(path):
            path = make_path(get_head(__file__), filename)
        if not exists(path):
            path = make_path(get_head(__file__), make_path('../..', filename))
        if not file_is_readable(path):
            error("%s: cannot open dictionary." % path, self.logger)
        return path

    # Read dictionary {{{2
    def _read_dictionary(self, path):
        try:
            with open(self.path) as f:
                return f.read()
        except IOError as err:
            error('%s: %s.' % (err.filename, err.strerror), self.logger)

    def validate(self, saved_hash):
        if saved_hash != self.hash:
            display("Warning: '%s' has changed." % self.path, self.logger)
            display("    " + "\n    ".join(wrap(' '.join([
                "This results in pass phrases that are inconsistent",
                "with those created in the past."]))), self.logger)

    def get_words(self):
        return self.words

# Master password class {{{1
# Responsible for reading and managing the data from the master password file.
class MasterPassword():
    # Constructor {{{2
    def __init__(self, path, dictionary, gpg, account, logger):
        self.path = path
        self.dictionary = dictionary
        self.gpg = gpg
        self.logger = logger
        self.data = self._read_master_password_file()
        self.passphrase = secrets.Passphrase(lambda text: display(text, logger))
        self.password = secrets.Password(lambda text: display(text, logger))
        self._validate_assumptions()
        self._set_master_password(account)

    # Read master password file {{{2
    def _read_master_password_file(self):
        data = {}
        try:
            with open(self.path, 'rb') as f:
                decrypted = self.gpg.decrypt_file(f)
                if not decrypted.ok:
                    error("%s\n%s" % (
                        "%s: unable to decrypt." % (self.path),
                        decrypted.stderr
                    ), self.logger)
                code = compile(decrypted.data, self.path, 'exec')
                exec(code, data)
        except IOError as err:
            error('%s: %s.' % (err.filename, err.strerror), self.logger)
        for ID in data.get('passwords', {}):
            if type(ID) != str:
                error('%s: master password ID must be a string.' % ID, self.logger)
        return data

    # Validate program assumptions {{{2
    def _validate_assumptions(self):
        # Check that dictionary has not changed
        self.dictionary.validate(self._get_field('dict_hash'))

        # Check that secrets.py has not changed
        secrets_path = make_path(get_head(__file__), 'secrets.py')
        try:
            with open(secrets_path) as f:
                contents = f.read()
        except IOError as err:
            secrets_path = make_path(get_head(__file__), '../../secrets.py')
            try:
                with open(secrets_path) as f:
                    contents = f.read()
            except IOError as err:
                error('%s: %s.' % (err.filename, err.strerror), self.logger)
        hash = hashlib.sha1(contents.encode('utf-8')).hexdigest()
        if hash != self._get_field('secrets_hash'):
            display("Warning: '%s' has changed." % secrets_path, self.logger)
            display("    " + "\n    ".join(wrap(' '.join([
                "This results in pass phrases that are inconsistent",
                "with those created in the past."]))), self.logger)

    # Get field {{{2
    def _get_field(self, key):
        try:
            return self.data[key]
        except KeyError:
            error("%s: cannot find '%s'" % (self.path, key), self.logger)

    # Set the master password {{{2
    # Get the master password associated with this account.
    # If there is none, use the default.
    # If there is no default, ask the user for a password.
    def _set_master_password(self, account):
        passwords = self._get_field('passwords')
        default_password = self._get_field('default_password')

        # Get the master password for this account.
        if account:
            password_id = account.get_master(default_password)
        else:
            password_id = default_password
        if password_id:
            try:
                self.master_password = passwords[password_id]
            except KeyError:
                error('%s: master password not found.' % password_id, self.logger)
        else:
            import getpass
            try:
                self.master_password = getpass.getpass()
                if not self.master_password:
                    display("Warning: Master password is empty.", self.logger)
            except KeyboardInterrupt:
                sys.exit()

    # Generate the password for the specified account {{{2
    def generate_password(self, account):
        # If there is an override, use it
        try:
            return self.data['password_overrides'][account.get_id()]
        except KeyError:
            pass

        # Otherwise generate a pass phrase or a password as directed
        password_type = account.get_password_type()
        if password_type == 'words':
            return self.passphrase.generate(
                self.master_password, account, self.dictionary)
        elif password_type == 'chars':
            return self.password.generate(self.master_password, account)
        else:
            error("%s: unknown password type (expected 'words' or 'chars').", self.logger)

    # Generate an answer to a security question {{{2
    # Only use pass phrases as answers to security questions, not passwords.
    def generate_answer(self, account, question_number):
        security_questions = account.get_security_questions()
        try:
            question = security_questions[question_number]
        except IndexError:
            error('There is no security question #%s.' % question_number, self.logger)
            return None
        answer = self.passphrase.generate(
            self.master_password, account, self.dictionary, question)
        return (question, answer)

# Accounts class {{{1
# Responsible for reading and managing the data from the accounts file.
class Accounts():
    # Constructor {{{2
    def __init__(self, path, logger, default_template = None):
        self.path = path
        self.logger = logger
        self.data = None
        self.accounts = self._read_accounts_file(path)
        if default_template:
            self.default_template = self.accounts.get(default_template, {})
            if not self.default_template:
                error("%s: default template not found." % default_template, self.logger)
        else:
            self.default_template = {}

        # Validate and repair the accounts
        string_fields = [
            'account', 'alphabet', 'autotype' 'email', 'master', 'prefix',
            'remarks', 'suffix' 'template', 'type', 'url', 'username',
            'version',
        ]
        integer_fields = ['num-chars', 'num-words']
        list_fields = ['security questions']
        list_or_string_fields = ['window']
        for ID in self.all_accounts(skip_templates=False):
            if type(ID) != str:
                error('%s: account ID must be a string.' % ID, self.logger)
            data = self.accounts[ID]
            for each in string_fields:
                if type(data.get(each, '')) != str:
                    display(' '.join([
                        "Invalid value for '%s' in %s account (%s).",
                        "Expected string. Ignoring" % (each, ID, data[each])]), logger)
                    del data[each]
            for each in integer_fields:
                if type(data.get(each, 0)) != int:
                    display(' '.join([
                        "Invalid value for '%s' in %s account (%s).",
                        "Expected integer. Ignoring" % (each, ID, data[each])]), logger)
                    del data[each]
            for each in list_fields:
                if type(data.get(each, [])) != list:
                    display(' '.join([
                        "Invalid value for '%s' in %s account (%s).",
                        "Expected list. Ignoring" % (each, ID, data[each])]), logger)
                    del data[each]
            for each in list_or_string_fields:
                if type(data.get(each, [])) != list and type(data.get(each, '')) != str:
                    display(' '.join([
                        "Invalid value for '%s' in %s account (%s).",
                        "Expected string or list. Ignoring" % (each, ID, data[each])]), logger)
                    del data[each]

    # Get a dictionary of all the fields for each account {{{2
    def all_accounts(self, skip_templates=True):
        for ID in self.accounts:
            if skip_templates and ID[0] == '=':
                pass
            else:
                yield ID

    # Get a particular field from each account {{{2
    def get_fields(self, field):
        for ID, data in self.accounts.items():
            if field in data and data[field]:
                yield (ID, data[field])

    # Read accounts file {{{2
    def _read_accounts_file(self, path):
        accounts_data = {}
        try:
            with open(self.path) as f:
                code = compile(f.read(), path, 'exec')
                exec(code, accounts_data)
        except IOError as err:
            error('%s: %s.' % (err.filename, err.strerror), self.logger)
        self.data = accounts_data
        try:
            return accounts_data['accounts']
        except KeyError:
            error("%s: defective accounts file, 'accounts' not found." % path, self.logger)

    # Get logfile {{{2
    def get_logfile(self):
        return self.data.get('logfile', None)

    # List templates {{{2
    # Templates are accounts whose ID starts with =.
    def all_templates(self):
        for key in self.accounts:
            if key[0] == '=':
                yield key

    # Account class {{{2
    # Responsible for holding all of the information for a particular account
    class Account():
        def __init__(self, ID, data):
            self.ID = ID
            self.data = data

        def get_id(self):
            return self.ID

        def get_data(self):
            return self.data

        def get_field(self, field):
            return self.data.get(field, None)

        def get_master(self, default):
            return self.data.get('master', default)

        def get_version(self):
            return self.data.get('version', '')

        def get_security_questions(self):
            return self.data.get('security questions', [])

        def get_autotype(self):
            return self.data.get('autotype', default_autotype)

        def get_password_type(self):
            return self.data.get('password-type', 'words')

        def get_num_chars(self, default):
            return self.data.get('num-chars', default)

        def get_num_words(self, default):
            return self.data.get('num-words', default)

        def get_alphabet(self, default):
            return self.data.get('alphabet', default)

        def get_prefix(self):
            return self.data.get('prefix', '')

        def get_suffix(self):
            return self.data.get('suffix', '')

    # Get account {{{2
    def get_account(self, account_id, level=0):
        if level > 20:
            error("%s: too many levels of templates, loop suspected." % account_id, self.logger)

        def find_account_id():
            # Account ID was not given by the user.
            # Try to determine it from title of active window.
            # First get the title from the active window.
            try:
                status, title = pipe('%s getactivewindow getwindowname' % xdotool)
            except ExecuteError as err:
                error(err.text, self.logger)
            title = title.strip()
            log('Focused window title: %s' % title, self.logger)

            # Look through window field in each account and see if any match.
            import fnmatch
            matches = []
            for ID, window in self.get_fields('window'):
                if type(window) == str:
                    if fnmatch.fnmatch(title, window):
                        matches.append(ID)
                elif type(window == list):
                    for each in window:
                        if fnmatch.fnmatch(title, each):
                            matches.append(ID)

            # Only a single match is allowed.
            if len(matches) == 1:
                log("'%s' account selected due to window title." % matches[0], self.logger)
                return matches[0]
            #elif matches:
            #    display("Active window title matches the following accounts:", self.logger)
            #    display("    %s" % ('\n    '.join(matches)), self.logger)
            elif matches:
                log("Window title matches the following accounts: '%s'." % "', '".join(matches), self.logger)
                from dialog import accountSelectDialog
                accounts = accountSelectDialog(sorted(matches))
                try:
                    log("User selected '%s' account." % accounts[0], self.logger)
                    return accounts[0]
                except TypeError:
                    pass
            error("Must specify desired account ID.", self.logger)

        # Validate account_id
        if not account_id:
            # User did not specify account ID on the command line.
            account_id = find_account_id()
        try:
            account = self.accounts[account_id]
        except KeyError:
            account = self.default_template
            if not account:
                display("Warning: account '%s' not found." % account_id, self.logger)

        # Get information from template
        template = account.get('template', None)
        if template:
            data = self.get_account(template, level=level+1).get_data()
        else:
            data = {}

        # Override template information with that from the account
        data.update(account)

        return Accounts.Account(account_id, data)

    # Find accounts {{{2
    def find_accounts(self, target):
        pattern = re.compile(target, re.I)
        for ID in self.all_accounts():
            if pattern.search(ID):
                yield ID

    # Search accounts {{{2
    def search_accounts(self, target):
        pattern = re.compile(target, re.I)
        for ID in self.all_accounts():
            data = self.accounts[ID]
            matches = bool(pattern.search(ID))
            for each in search_fields:
                if pattern.search(data.get(each, '')):
                    matches = True
                    break
            if matches:
                yield ID

# PasswordWriter class {{{1
# Used to get account information to the user.
class PasswordWriter():
    # PasswordWriter is responsible for sending output to the user. It has three
    # backends, one that writes to standard out, one that writes to the
    # clipboard, and one that autotypes. To accommodate the three backends the
    # output is gathered up and converted into a script. That script is
    # interpreted by the appropriate backend to produce the output. the script
    # is a sequence of commands each with an argument. Internally the script is
    # saved as a list of tuples. The first value in the tuple is the name of the 
    # command. Several commands are supported.
    #    write_verbatim() --> ('verb', <str>)
    #        Outputs the argument verbatim.
    #    write_account_entry() --> ('interp', <label>)
    #        Interpolates information from the account file into the output.
    #        The argument is the item to be interpolated (username, url, etc.)
    #    write_password() --> ('password')
    #        Outputs the password as a secret (the output does its best to keep
    #        it secure).
    #    write_question() --> ('question', [<int>])
    #        Outputs security question <int>, or all the available security
    #        questions if <int> is not given. The answer is not included in the
    #        response.
    #    write_answer() --> ('answer', <int>)
    #        Outputs the answer to a security question as a secret (the output
    #        does its best to keep it secure).  The argument is the index
    #        of the question.
    #    sleep() --> ('sleep', <real>)
    #        Waits before continuing. The argument is the number of seconds to
    #        wait.

    # Constructor {{{2
    def __init__(self, output, password, wait = 60, logger = None):
        """
        output is either 'c' for clipboard, 't' for autotype, and 's' for
        stdout.
        """
        assert(output in ['c', 't', 's'])
        self.output = output
        self.wait = wait
        self.password = password
        self.logger = logger if logger else password.logger
        self.script = []

    # Is empty {{{2
    def is_empty(self):
        return not self.script

    # Actions {{{2
    def write_verbatim(self, text):
        self.script += [('verb', text)]

    def write_account_entry(self, label):
        self.script += [('interp', label)]

    def write_password(self):
        self.script += [('password',)]

    def write_question(self, num=None):
        self.script += [('question', num)]

    def write_answer(self, num):
        self.script += [('answer', num)]

    def sleep(self, delay):
        self.script += [('sleep', delay)]

    # Parse autotype script {{{2
    # User has requested autotype. Look up and parse the autotype script. 
    def write_autotype(self):
        regex=re.compile('({\w+})')
        for term in regex.split(self.password.account.get_autotype()):
            if term and term[0] == '{' and term[-1] == '}':
                cmd = term[1:-1].lower()
                if cmd in ['username', 'account', 'url', 'email', 'remarks']:
                    self.write_account_entry(cmd)
                elif cmd == 'password':
                    self.write_password()
                elif cmd == 'tab':
                    self.write_verbatim('\t')
                elif cmd == 'return':
                    self.write_verbatim('\n')
                elif cmd.startswith('sleep'):
                    cmd = cmd.split()
                    try:
                        assert cmd[0] == 'sleep'
                        assert len(cmd) == 2
                        self.sleep(float(cmd[1]))
                    except (AssertionError, TypeError):
                        display("ERROR in autotype: %s" % term, self.logger)
                        return
                elif cmd.startswith('question'):
                    cmd = cmd.split()
                    try:
                        assert cmd[0] == 'question'
                        assert len(cmd) == 2
                        self.write_question(int(cmd[1]))
                    except (AssertionError, TypeError, IndexError):
                        display("ERROR in autotype: %s" % term, self.logger)
                        return
                elif cmd.startswith('answer'):
                    cmd = cmd.split()
                    try:
                        assert cmd[0] == 'answer'
                        assert len(cmd) == 2
                        self.write_answer(int(cmd[1]))
                    except (AssertionError, TypeError, IndexError):
                        display("ERROR in autotype: %s" % term, self.logger)
                        return
                else:
                    display("ERROR in autotype: %s" % term, self.logger)
                    return
            else:
                if (term):
                    self.write_verbatim(term)

    # Process output {{{2
    def process_output(self):
        if self.output == 't':
            self._process_output_to_autotype()
        elif self.output == 'c':
            self._process_output_to_clipboard()
        else:
            self._process_output_to_stdout()

    # Process output to standard output {{{3
    def _process_output_to_stdout(self):
        # Send output to stdout with the labels.
        def display_secret(label, secret):
            import cursor
            text = ': '.join([cursor.color(label, 'magenta'), secret])
            if self.wait:
                try:
                    cursor.write(text);
                    sleep(self.wait)
                    cursor.clear()
                except KeyboardInterrupt:
                    cursor.clear()
            else:
                print(text)

        # Execute the script
        for action in self.script:
            if action[0] == 'interp':
                value = self.password.account.get_field(action[1])
                if value:
                    if '\n' in value:
                        print(action[1].upper() + ':\n' + indent(value.strip(), '    '))
                    else:
                        print(action[1].upper() + ':', value.rstrip())
            elif action[0] == 'password':
                display_secret(
                    'PASSWORD',
                    self.password.generate_password()
                )
            elif action[0] == 'question':
                questions = self.password.account.get_field('security questions')
                if questions:
                    if action[1] == None:
                        for index, question in enumerate(questions):
                            print('QUESTION %d: %s' % (index, question))
                    else:
                        try:
                            print('QUESTION %d: %s' % (action[1], questions[action[1]]))
                        except IndexError:
                            print('QUESTION %d: <not available>' % action[1])
            elif action[0] == 'answer':
                question, answer = self.password.generate_answer(action[1])
                if answer:
                    display_secret(question, answer)
            else:
                raise NotImplementedError
        log('Writing to stdout.', self.logger)

    # Process output to clipboard {{{3
    def _process_output_to_clipboard(self):
        # Send output to clipboard without the labels.
        lines = []

        # Execute the script
        for action in self.script:
            if action[0] == 'interp':
                value = self.password.account.get_field(action[1])
                if value:
                    lines += [value.rstrip()]
                else:
                    lines += ['<%s unknown>' % action[1]]
            elif action[0] == 'password':
                lines += [self.password.generate_password()]
            elif action[0] == 'question':
                questions = self.password.account.get_field('security questions')
                if action[1] == None:
                    for index, question in enumerate(questions):
                        lines += ['question %d: %s' % (index, question)]
                else:
                    try:
                        lines += ['question %d: %s' % (action[1], questions[action[1]])]
                    except IndexError:
                        lines += ['question %d: <not available>' % action[1]]
            elif action[0] == 'answer':
                question, answer = self.password.generate_answer(action[1])
                if answer:
                    lines += [answer]
            else:
                raise NotImplementedError
        text='\n'.join(lines)
        log('Writing to clipboard.', self.logger)

        # Use 'xsel' to put the information on the clipboard.
        # This represents a vunerability, if someone were to replace xsel they
        # could sell my passwords. This is why I use an absolute path. I tried
        # to access the clipboard directly using GTK but I cannot get the code
        # to work.
        try:
            pipe('%s -b -i' % xsel, text)
        except ExecuteError as err:
            error(err.message, self.logger)
        try:
            sleep(self.wait)
        except KeyboardInterrupt:
            pass
        try:
            execute("%s -b -c" % xsel)
        except ExecuteError as err:
            error(err.message, self.logger)

        # Use Gobject Introspection (GTK) to put the information on the
        # clipboard (for some reason I cannot get this to work).
        """
        try:
            from gi.repository import Gtk, Gdk

            clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clipboard.set_text(text, len(text))
            clipboard.store()
            sleep(self.wait)
            clipboard.clear()
        except ImportError:
            error('Clipboard is not supported.')
        """

    # Process output to autotype {{{3
    def _process_output_to_autotype(self):
        # Mimic a keyboard to send output to the active window.

        def autotype(text):
            # Use 'xdotool' to mimic the keyboard.
            # For reasons I do not understand, sending a newline to xdotool does
            # not always result in a newline coming out. So separate out the
            # newlines and send them using as an explicit 'key' stroke.
            regex=re.compile(r'(\n)')
            segments = regex.split(text)
            try:
                for segment in segments:
                    if segment == '\n':
                        execute('%s key Return' % xdotool)
                    elif segment != '':
                        # send text to xdotool thru stdin so it cannot be seen with ps
                        pipe('%s -' % xdotool, 'getactivewindow type "%s"' % segment)
            except ExecuteError as err:
                error(err.message, self.logger)

        # Execute the script
        text = []
        scrubbed = []
        sleep(0.25)
        for action in self.script:
            if action[0] == 'verb':
                text += [action[1]]
                scrubbed += [action[1]]
            elif action[0] == 'sleep':
                autotype(''.join(text))
                text = []
                sleep(action[1])
                scrubbed += ['<sleep %s>' % action[1]]
            elif action[0] == 'interp':
                value = self.password.account.get_field(action[1])
                if value:
                    value = value.rstrip()
                else:
                    value = '<%s unknown>' % action[1]
                text += [value]
                scrubbed += [value]
            elif action[0] == 'password':
                text += [self.password.generate_password()]
                scrubbed += ['<<password>>']
            elif action[0] == 'question':
                questions = self.password.account.get_field('security questions')
                if action[1] == None:
                    for index, question in enumerate(questions):
                        value = 'question %d: %s' % (index, question)
                else:
                    try:
                        value = 'question %d: %s' % (action[1], questions[action[1]])
                    except IndexError:
                        value = 'question %d: <not available>' % action[1]
                text += [value]
                scrubbed += [value]
            elif action[0] == 'answer':
                question, answer = self.password.generate_answer(action[1])
                if answer:
                    text += [answer]
                    scrubbed += ["<<answer to '%s'>>" % question]
            else:
                raise NotImplementedError
        log('Autotyping "%s".' % ''.join(scrubbed), self.logger)
        autotype(''.join(text))

# Password class {{{1
class Password:
    """Password Generator"""
    # Constructor {{{2
    def __init__(self, settings_dir = None, logger = None):
        """Arguments:
           settings_dir
               Path to the settings directory. Generally only specified when
               testing.
           logger: Object that provides display(msg), log(msg), and error(msg)
               methods:
                   display() is called when a message is to be sent to the user
                   log() is called when a message is to be logged
                   exit() is called when an error has occurred.
        """

        if not settings_dir:
            settings_dir = default_settings_dir
        self.settings_dir = expand_path(settings_dir)
        if not logger:
            logger = Logging()
        self.logger = logger

        # Get the dictionary
        self.dictionary = Dictionary(
                dictionary_filename, self.settings_dir, logger)

        # Activate GPG
        self.gpg = gnupg.GPG()

        self.master_password_path = make_path(
                self.settings_dir, master_password_filename)
        self.accounts_path = make_path(
                self.settings_dir, accounts_filename)

    # Create initial settings files {{{2
    # Will create initial versions of the master password file and the accounts
    # file, but only if they do not already exist. The master password file is
    # encrypted with the GPG ID given on the command line, which should be the
    # users.
    def create_initial_settings_files(self, gpg_id):
        """Create initial version of settings files for the user.
        
           Arguments:
           Requires user's GPG ID as the only argument.
        """

        def createFile(filename, contents, encrypt=False):
            if encrypt:
                encrypted = self.gpg.encrypt(contents, gpg_id,
                        always_trust=True, armor=True)
                if not encrypted.ok:
                    error("%s: unable to encrypt.\n" % (filename) + encrypted.stderr, self.logger)
                contents = str(encrypted)
            if is_file(filename):
                display("%s: already exists" % filename, self.logger)
            else:
                try:
                    with open(filename, 'w') as file:
                        file.write(contents)
                    os.chmod(filename, 0o600)
                    display("%s: created" % filename, self.logger)
                except IOError as err:
                    error('%s: %s.' % (err.filename, err.strerror), self.logger)

        # Generate a random long string to act as the default password
        def generate_random_string():
            def partition(bytestr):
                for each in list(bytestr):
                    yield each

            digest = os.urandom(64)
            import string
            alphabet = string.ascii_letters + string.digits + string.punctuation
            password = ''
            for index in partition(digest):
                password += alphabet[index % len(alphabet)]
            return password

        mkdir(self.settings_dir)
        if self.settings_dir == default_settings_dir:
            default_password = generate_random_string()
        else:
            # if settings_dir is not the default_settings_dir, then this is most
            # probably a test, in which case we do not want to use a random
            # password as it would cause the test results to vary.
            default_password = '<< test pass phrase -- do not use >>'
        createFile(
            self.master_password_path,
            master_password_file_initial_contents % (
                self.dictionary.hash, secrets_sha1, default_password
            ), encrypt=True
        )
        createFile(
            self.accounts_path,
            accounts_file_initial_contents % make_path(self.settings_dir, 'log'))

    # Open the accounts file {{{2
    def read_accounts(self, default_template = default_template):
        """Read accounts file.

           Required before secrets can be generated or accounts can be queried.
           Arguments:
           default_template:
               The template to be used if one is not found in the account.
        """
        accounts = Accounts(self.accounts_path, self.logger, default_template)
        self.accounts = accounts
        self.all_templates = accounts.all_templates
        self.all_accounts = accounts.all_accounts
        self.find_accounts = accounts.find_accounts
        self.search_accounts = accounts.search_accounts
        self.logger.set_logfile(accounts.get_logfile())

    # Get account {{{2
    def get_account(self, account_id):
        account = self.accounts.get_account(account_id)
        self.account = account
        log('Using account: %s.' % account.get_id(), self.logger)
        self.master_password = MasterPassword(
                self.master_password_path, self.dictionary, self.gpg,
                account, self.logger)
        return account

    def generate_password(self):
        return self.master_password.generate_password(self.account)

    def generate_answer(self, question_number):
        return self.master_password.generate_answer(self.account, question_number)

# PasswordError class {{{1
class PasswordError(Exception):
    def __init__(self, message):
        self.message = message

# Main {{{1
if __name__ == "__main__":
    cmd_line = CommandLine(sys.argv)
    try:
        with Logging(argv=sys.argv) as logger:
            password = Password(logger=logger)

            # If requested, generate initial versions of the settings file and
            # exit
            if cmd_line.init:
                password.create_initial_settings_files(cmd_line.init)
                sys.exit()

            # Open the accounts file
            password.read_accounts(cmd_line.default_template)

            # If requested, list the available templates and then exit
            if cmd_line.list_templates:
                print("templates:\n   " + '\n   '.join(sorted(password.all_templates())))
                sys.exit()

            # If requested, search the account database and exit after printing
            # results
            if cmd_line.find:
                print(cmd_line.find, end=':\n   ')
                print('\n   '.join(password.find_accounts(cmd_line.find)))
                sys.exit()

            if cmd_line.search:
                print(cmd_line.search, end=':\n   ')
                print('\n   '.join(password.search_accounts(cmd_line.search)))
                sys.exit()

            # Get the requested account
            account = password.get_account(cmd_line.account)

            # Create the secrets writer
            style = 'c' if cmd_line.clipboard else 't' if cmd_line.autotype else 's'
            writer = PasswordWriter(style, password, cmd_line.wait, logger)

            # Process the users output requests
            if cmd_line.autotype:
                writer.write_autotype()
            else:
                if cmd_line.username or cmd_line.all:
                    writer.write_account_entry('username')
                if cmd_line.account_number or cmd_line.all:
                    writer.write_account_entry('account')
                if cmd_line.email or cmd_line.all:
                    writer.write_account_entry('email')
                if cmd_line.url or cmd_line.all:
                    writer.write_account_entry('url')
                if cmd_line.remarks or cmd_line.all:
                    writer.write_account_entry('remarks')
                if cmd_line.all:
                    writer.write_question()
                if cmd_line.question != None:
                    writer.write_answer(cmd_line.question)
                if cmd_line.password or writer.is_empty():
                    writer.write_password()

            # Output everything that the user requested.
            writer.process_output()
    except PasswordError as err:
        sys.exit('%s: %s' % (cmd_line.prog_name, err.message))
    exit(logger)
