#!/usr/bin/env python
"""Generates passwords and pass phrases based on stored account information."""

# Imports {{{1
from __future__ import print_function, division
from fileutils import (
    makePath as make_path,
    getTail as get_tail,
    getHead as get_head,
    getExt as get_extension,
    isFile as is_file,
    expandPath as expand_path,
    fileIsReadable as file_is_readable,
    mkdir, exists,
    execute, pipe, ExecuteError
)
import secrets
import cursor
from textwrap import dedent, wrap
from time import sleep
import argparse
import gnupg
import hashlib
import traceback
import re
import os
import sys

# Globals {{{1
DEFAULT_SETTINGS_DIR = '~/.config/pw'
MASTER_PASSWORD_FILENAME = 'master.gpg'
ACCOUNTS_FILENAME = 'accounts'
    # accounts file will be encrypted if you add .gpg or .asc extension
DICTIONARY_FILENAME = 'words'
LOG_FILENAME = 'log'
ARCHIVE_FILENAME = 'archive.gpg'
DEFAULT_TEMPLATE = "=words"
DEFAULT_AUTOTYPE = "{username}{tab}{password}{return}"
SEARCH_FIELDS = ['username', 'account', 'email', 'url', 'remarks']
# Use absolute paths for xdotool and xsel
# Makes it harder for someone to replace them so as to expose the secrets.
XDOTOOL = '/usr/bin/xdotool'
XSEL = '/usr/bin/xsel'
SECRETS_SHA1 = "5d0182e4b939352b352027201008e8af473ee612"
CHARSETS_SHA1 = "6c9644ab97b1f53f982f70e2808f0f1e850e1fe1"

# Initial master password file {{{2
MASTER_PASSWORD_FILE_INITIAL_CONTENTS = dedent('''\
    dict_hash = "%s"      # DO NOT CHANGE THIS LINE
    secrets_hash = "%s"   # DO NOT CHANGE THIS LINE
    charsets_hash = "%s"  # DO NOT CHANGE THIS LINE

    accounts_file = "%s"
    passwords = {
        'default': """<%s>""",  # DO NOT CHANGE THIS LINE
    }
    default_password = 'default'
    password_overrides = {
        '<account>': """<place password here>""",
    }
''')

# Initial accounts file {{{2
ACCOUNTS_FILE_INITIAL_CONTENTS = dedent('''\
    # Account information
    #
    # Add information about each of your accounts to the accounts dictionary.
    #
    # You can use the dedent function to strip leading whitespace from
    # multi-line remarks.  You can use the character sets and exclude function
    # to create alphabets for you character-base passwords.
    #
    # Example:
    # To create an alphabet with all characters except tabs use either:
    #     'alphabet': exclude(printable, '\\t')
    # or:
    #     'alphabet': alphanumeric + punctuation + ' '

    from textwrap import dedent
    from charsets import (
        exclude, lowercase, uppercase, letters, digits, alphanumeric,
        hexdigits, punctuation, whitespace, printable, distinguishable)

    # The desired location of the log file (use an absolute path)
    log_file = '%s'

    # The desired location of the archive file
    # (use an absolute path, end file in .gpg)
    archive_file = '%s'

    # The GPG ID of the user (used to encrypt archive.gpg file)
    gpg_id = '%s'

    # Account Information
    # Add your account information here ...
    accounts = {
        # Templates
        # The first view are intended to be templates.
        # Any account can be used as a template for another account.
        # Those that are designated as templates (ID starts with +) cannot be
        # used as an actual account and will not be listed in find and search
        # results. Feel free to modify, delete, or add your own templates.
        # You might want to choose short names with no spaces or glob
        # characters for those templates you plan to use from the command line.
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
        "=anum": {  # typically used for web passwords (contains only easily distinguished alphanumeric characters)
            'password-type': 'chars',
            'num-chars': 12,
            'alphabet': distinguishable,
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
        #       'num-words': <int>, # number of words in passphrases
        #       'separator': ' ',   # separates words in passphrases
        #       'num-chars': <int>, # number of characters in passwords
        #       'alphabet': distinguishable
        #                           # character set used in passwords
        #                           # construct from character sets
        #       'prefix': '',       # added to the front of passwords
        #       'suffix': '',       # added to the end of passwords
        #   },
        }
    additional_accounts = []
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
def terminate(logger):
    log('Terminates normally.', logger)
    sys.exit()


# Indent a string {{{2
# This should be provided by textwrap, but is not available from older versions
def indent(text, prefix='    '):
    return '\n'.join(
        [prefix + line if line else line for line in text.split('\n')])


# CommandLine class {{{1
class CommandLine:
    def __init__(self, argv):
        self.prog_name = get_tail(argv[0])
        parser = argparse.ArgumentParser(
            add_help=False, description="Generate strong and unique password.")
        arguments = parser.add_argument_group('arguments')
        arguments.add_argument(
            'account', nargs='?', default='',
            help="Generate password specific to this account.")
        parser.add_argument(
            '-q', '--question', type=int, metavar='<N>',
            default=None, help="Output security question N.")
        parser.add_argument(
            '-P', '--password', action='store_true',
            help="Output the password (default if nothing else is requested).")
        parser.add_argument(
            '-N', '--username', action='store_true',
            help="Output the username.")
        parser.add_argument(
            '-A', '--account-number', action='store_true',
            help="Output the account number.")
        parser.add_argument(
            '-E', '--email', action='store_true', help="Output the email.")
        parser.add_argument(
            '-U', '--url', action='store_true', help="Output the URL.")
        parser.add_argument(
            '-R', '--remarks', action='store_true',
            help="Output remarks.")
        parser.add_argument(
            '-i', '--info', action='store_true',
            help="Output everything, except the password.")
        parser.add_argument(
            '-a', '--all', action='store_true',
            help="Output everything, including the password.")
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            '-c', '--clipboard', action='store_true',
            help="Write output to clipboard rather than stdout.")
        group.add_argument(
            '-t', '--autotype', action='store_true',
            help=(' '.join([
                "Mimic keyboard to send output to the active window rather",
                "than stdout. In this case any command line arguments that",
                "specify what to output are ignored and the autotype entry",
                "scripts the output."])))
        parser.add_argument(
            '-f', '--find', type=str, metavar='<str>',
            help=(' '.join([
                "List any account that contains the given string",
                "in its ID or aliases."])))
        parser.add_argument(
            '-s', '--search', type=str, metavar='<str>',
            help=(' '.join([
                "List any account that contains the given string in",
                "%s, or its ID." % ', '.join(SEARCH_FIELDS)])))
        parser.add_argument(
            '-T', '--template',
            type=str, metavar='<template>', default=None,
            help="Template to use if account is not found.")
        parser.add_argument(
            '-l', '--list', action='store_true',
            help=(' '.join([
                "List available master passwords and templates (only pure",
                "templates are listed, not accounts, even though accounts",
                "can be used as templates)."])))
        parser.add_argument(
            '-w', '--wait', type=float, default=60, metavar='<secs>',
            help=(' '.join([
                "Wait this long before clearing the secret",
                "(use 0 to disable)."])))
        parser.add_argument(
            '--archive', action='store_true',
            help=("Archive all the secrets to %s." % make_path(
                DEFAULT_SETTINGS_DIR, ARCHIVE_FILENAME)))
        parser.add_argument(
            '--changed', action='store_true',
            help=(
                "Identify all secrets that have changed since last archived."))
        parser.add_argument(
            '-I', '--init', type=str, metavar='<GPG ID>',
            help=(' '.join([
                "Initialize the master password and account files in",
                DEFAULT_SETTINGS_DIR,
                "(but only if they do not already exist)."])))
        parser.add_argument(
            '-h', '--help',  action='store_true',
            help="Show this help message and exit.")

        args = parser.parse_args()

        # If requested, print help message and exit
        if args.help:
            parser.print_help()
            sys.exit()

        # Save all the command line arguments as attributes of self
        self.__dict__.update(args.__dict__)

    def name_as_invoked(self):
        return self.prog_name


# Logging class {{{1
# Log messages to a file
class Logging:
    def __init__(self, logfile=None, argv=None, prog_name=None):
        if logfile:
            self.logfile = self.set_logfile(logfile)
        else:
            self.logfile = None
        self.cache = []
        if argv:
            try:
                from datetime import datetime
                now = datetime.now().strftime(
                    " on %A, %d %B %Y at %I:%M:%S %p")
            except:
                now = ""
            self.log("Invoked as '%s'%s." % (' '.join(argv), now))
        self.prog_name = prog_name
        if argv and not prog_name:
            self.prog_name = argv[0]

    # Open the logfile.
    def set_logfile(self, logfile):
        self.logfile = None
        if logfile:
            try:
                filename = expand_path(logfile)
                self.logfile = open(filename, 'w')
                os.chmod(filename, 0o600)
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
class Dictionary:
    def __init__(self, filename, settings_dir, logger):
        path = self._find_dictionary(filename, settings_dir)
        self.path = path
        contents = self._read_dictionary()
        self.hash = hashlib.sha1(contents.encode('utf-8')).hexdigest()
        self.words = contents.split()
        self.logger = logger

    # Find dictionary {{{2
    # Finds the file that contains the dictionary of words used to construct
    # pass phrases. Initially looks in the settings directory, if not there
    # look in install directory.
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
    def _read_dictionary(self):
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
class MasterPassword:
    # Constructor {{{2
    def __init__(self, path, dictionary, gpg, logger):
        self.path = path
        self.dictionary = dictionary
        self.gpg = gpg
        self.logger = logger
        self.data = self._read_master_password_file()
        self.passphrase = secrets.Passphrase(
            lambda text: display(text, logger))
        self.password = secrets.Password(
            lambda text: display(text, logger))
        self._validate_assumptions()

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
        except SyntaxError as err:
            traceback.print_exc(0)
            sys.exit()
        for ID in data.get('passwords', {}):
            if type(ID) != str:
                error(
                    '%s: master password ID must be a string.' % ID,
                    self.logger)
        return data

    # Validate program assumptions {{{2
    def _validate_assumptions(self):
        # Check that dictionary has not changed
        self.dictionary.validate(self._get_field('dict_hash'))

        # Check that secrets.py and charset.py have not changed
        for each in ['secrets', 'charsets']:
            path = make_path(get_head(__file__), each + '.py')
            try:
                with open(path) as f:
                    contents = f.read()
            except IOError as err:
                path = make_path(get_head(__file__), '../..', each + '.py')
                try:
                    with open(path) as f:
                        contents = f.read()
                except IOError as err:
                    error('%s: %s.' % (err.filename, err.strerror), self.logger)
            hash = hashlib.sha1(contents.encode('utf-8')).hexdigest()
            if hash != self._get_field('%s_hash' % each):
                display("Warning: '%s' has changed." % path, self.logger)
                display("    " + "\n    ".join(wrap(' '.join([
                    "This results in passwords that are inconsistent",
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
    def set_master_password(self, account):
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
                error(
                    '%s: master password not found.' % password_id,
                    self.logger)
        else:
            import getpass
            try:
                self.master_password = getpass.getpass()
                if not self.master_password:
                    display("Warning: Master password is empty.", self.logger)
            except KeyboardInterrupt:
                sys.exit()

    def password_names(self):
        # return a list that contains the name of the master passwords
        return self._get_field('passwords').keys()

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
            error(
                "%s: unknown password type (expected 'words' or 'chars').",
                self.logger)

    # Generate an answer to a security question {{{2
    # Only use pass phrases as answers to security questions, not passwords.
    def generate_answer(self, account, question):
        if type(question) == int:
            security_questions = account.get_security_questions()
            try:
                question = security_questions[question]
            except IndexError:
                error(
                    'There is no security question #%s.' % question,
                    self.logger)
        answer = self.passphrase.generate(
            self.master_password, account, self.dictionary, question)
        return (question, answer)


# Accounts class {{{1
# Responsible for reading and managing the data from the accounts file.
class Accounts:
    # Constructor {{{2
    def __init__(self, path, logger, gpg, template=None):
        self.path = path
        if not exists(path):
            # If file does not exist, look for encrypted versions
            for ext in ['gpg', 'asc']:
                new_path = '.'.join([path, ext])
                if exists(new_path):
                    self.path = new_path
                    break

        self.logger = logger
        self.gpg = gpg
        self.data = None
        self.accounts = self._read_accounts_file()
        if template:
            self.template = self.accounts.get(template, {})
            if not self.template:
                error("%s: template not found." % template, self.logger)
        else:
            self.template = {}

        # Validate and repair each account, then process any aliases
        string_fields = [
            'alphabet', 'autotype' 'email', 'master', 'prefix',
            'remarks', 'separator', 'suffix' 'template', 'type', 'url',
            'username', 'version'
        ]
        integer_fields = ['num-chars', 'num-words']
        list_fields = ['security questions', 'aliases']
        list_or_string_fields = ['account', 'window']
        self.aliases = {}
        for ID in self.all_accounts(skip_templates=False):
            if type(ID) != str:
                error('%s: account ID must be a string.' % ID, self.logger)
            data = self.accounts[ID]

            # check the types of the data in the various fields
            for each in string_fields:
                if type(data.get(each, '')) != str:
                    display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                each, ID, data[each]),
                            "Expected string, ignoring."]),
                        logger)
                    del data[each]
            for each in integer_fields:
                if type(data.get(each, 0)) != int:
                    display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                each, ID, data[each]),
                            "Expected integer, ignoring."]),
                        logger)
                    del data[each]
            for each in list_fields:
                if type(data.get(each, [])) != list:
                    display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                each, ID, data[each]),
                            "Expected list, ignoring."]),
                        logger)
                    del data[each]
            for each in list_or_string_fields:
                if (
                    type(data.get(each, [])) != list and
                    type(data.get(each, '')) != str
                ):
                    display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                each, ID, data[each]),
                            "Expected string or list, ignoring."]),
                        logger)
                    del data[each]

            def addToAliases(ID, name):
                if name in self.aliases:
                    error(
                        ' '.join([
                            "Alias %s" % (name),
                            "from account %s" % (
                                ID if name != ID else self.aliases[name]),
                            "duplicates an account name or previous entry,",
                            "ignoring."]),
                        self.logger)
                else:
                    self.aliases[name] = ID

            # add ID to the aliases and then add the actual aliases
            addToAliases(ID, ID)
            for alias in data.get('aliases', []):
                addToAliases(ID, alias)

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
    def _read_accounts_file(self):
        accounts_data = {}
        try:
            if get_extension(self.path) in ['gpg', 'asc']:
                # Accounts file is GPG encrypted, decrypt it before loading
                with open(self.path, 'rb') as f:
                    decrypted = self.gpg.decrypt_file(f)
                    if not decrypted.ok:
                        error("%s\n%s" % (
                            "%s: unable to decrypt." % (self.path),
                            decrypted.stderr
                        ), self.logger)
                    code = compile(decrypted.data, self.path, 'exec')
                    exec(code, accounts_data)
            else:
                # Accounts file is not encrypted
                with open(self.path) as f:
                    code = compile(f.read(), self.path, 'exec')
                    exec(code, accounts_data)
            additional_accounts = accounts_data.get('additional_accounts', [])
            if type(additional_accounts) == str:
                additional_accounts = additional_accounts.split()
            more_accounts = {}
            for each in additional_accounts:
                path = make_path(get_head(self.path), each)
                if get_extension(path) in ['gpg', 'asc']:
                    # Accounts file is GPG encrypted, decrypt it
                    with open(path, 'rb') as f:
                        decrypted = self.gpg.decrypt_file(f)
                        if not decrypted.ok:
                            error("%s\n%s" % (
                                "%s: unable to decrypt." % (path),
                                decrypted.stderr
                            ), self.logger)
                        code = compile(decrypted.data, path, 'exec')
                        exec(code, more_accounts)
                else:
                    # Accounts file is not encrypted
                    with open(path) as f:
                        code = compile(f.read(), path, 'exec')
                        exec(code, more_accounts)
                existing_accounts = set(accounts_data['accounts'].keys())
                new_accounts = set(more_accounts['accounts'].keys())
                keys_in_common = sorted(
                    existing_accounts.intersection(new_accounts))
                if len(keys_in_common) > 2:
                    display("%s: overrides existing accounts:\n    %s" % (
                        path, ',\n    '.join(sorted(keys_in_common))),
                        self.logger)
                elif keys_in_common:
                    display("%s: overrides existing account: %s" % (
                        path, keys_in_common[0]), self.logger)
                accounts_data['accounts'].update(more_accounts['accounts'])
        except IOError as err:
            error('%s: %s.' % (err.filename, err.strerror), self.logger)
        except SyntaxError as err:
            traceback.print_exc(0)
            sys.exit()
        self.data = accounts_data
        try:
            return accounts_data['accounts']
        except KeyError:
            error(
                "%s: defective accounts file, 'accounts' not found." % self.path,
                self.logger)

    # Get log file {{{2
    def get_log_file(self):
        return self.data.get(
            'log_file',
            make_path(DEFAULT_SETTINGS_DIR, LOG_FILENAME))

    # Get archive file {{{2
    def get_archive_file(self):
        return self.data.get(
            'archive_file',
            make_path(DEFAULT_SETTINGS_DIR, ARCHIVE_FILENAME))

    # Get gpg it {{{2
    def get_gpg_id(self):
        try:
            return self.data['gpg_id']
        except KeyError:
            error(
                "'gpg_id' missing from %s (see 'man 5 pw')." % self.path,
                self.logger)

    # List templates {{{2
    # Templates are accounts whose ID starts with =.
    def all_templates(self):
        for key in self.accounts:
            if key[0] == '=':
                yield key

    # Account class {{{2
    # Responsible for holding all of the information for a particular account
    class Account:
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
            return self.data.get('autotype', DEFAULT_AUTOTYPE)

        def get_password_type(self):
            return self.data.get('password-type', 'words')

        def get_num_chars(self, default):
            return self.data.get('num-chars', default)

        def get_num_words(self, default):
            return self.data.get('num-words', default)

        def get_alphabet(self, default):
            return self.data.get('alphabet', default)

        def get_separator(self, default):
            return self.data.get('separator', default)

        def get_prefix(self):
            return self.data.get('prefix', '')

        def get_suffix(self):
            return self.data.get('suffix', '')

    # Get account {{{2
    def get_account(self, account_id, level=0):
        if level > 20:
            error(
                "%s: too many levels of templates, loop suspected." % (
                    account_id),
                self.logger)

        def find_account_id():
            # Account ID was not given by the user.
            # Try to determine it from title of active window.
            # First get the title from the active window.
            try:
                status, title = pipe(
                    '%s getactivewindow getwindowname' % XDOTOOL)
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
                log(
                    "'%s' account selected due to window title." % matches[0],
                    self.logger)
                return matches[0]
            #elif matches:
            #    display(
            #        "Active window title matches the following accounts:",
            #        self.logger)
            #    display("    %s" % ('\n    '.join(matches)), self.logger)
            elif matches:
                log(
                    "Window title matches the following accounts: '%s'." % (
                        "' '".join(matches)),
                    self.logger)
                from dialog import accountSelectDialog
                accounts = accountSelectDialog(sorted(matches))
                try:
                    log(
                        "User selected '%s' account." % accounts[0],
                        self.logger)
                    return accounts[0]
                except TypeError:
                    pass
            error("cannot determine desired account ID.", self.logger)

        # Validate account_id
        if not account_id:
            # User did not specify account ID on the command line.
            account_id = find_account_id()
        try:
            account_id = self.aliases[account_id]
            account = self.accounts[account_id]
        except KeyError:
            account = self.template
            display(
                "Warning: account '%s' not found." % account_id,
                self.logger)

        # Get information from template
        template = account.get('template', None)
        if template:
            data = self.get_account(template, level=level+1).get_data()
        else:
            data = {}

        # Override template information with that from the account
        data.update(account)

        return Accounts.Account(account_id, data)

    # Find and Search accounts {{{2
    @staticmethod
    def _inID(pattern, ID):
        return bool(pattern.search(ID))

    @staticmethod
    def _inAliases(pattern, acct):
        for each in acct.get('aliases', ''):
            if pattern.search(each):
                return True
        return False

    @staticmethod
    def _inSearchField(pattern, acct):
        for each in SEARCH_FIELDS:
            if pattern.search(acct.get(each, '')):
                return True
        return False

    def find_accounts(self, target):
        pattern = re.compile(target, re.I)
        for ID in self.all_accounts():
            if (
                    self._inID(pattern, ID) or
                    self._inAliases(pattern, self.accounts[ID])):
                yield ID, self.accounts[ID].get('aliases', [])

    # Search accounts {{{2
    def search_accounts(self, target):
        pattern = re.compile(target, re.I)
        for ID in self.all_accounts():
            acct = self.accounts[ID]
            if (
                    self._inID(pattern, ID) or
                    self._inAliases(pattern, acct) or
                    self._inSearchField(pattern, acct)):
                yield ID, self.accounts[ID].get('aliases', [])


# PasswordWriter class {{{1
# Used to get account information to the user.
class PasswordWriter:
    # PasswordWriter is responsible for sending output to the user. It has
    # three backends, one that writes to standard out, one that writes to the
    # clipboard, and one that autotypes. To accommodate the three backends the
    # output is gathered up and converted into a script. That script is
    # interpreted by the appropriate backend to produce the output. the script
    # is a sequence of commands each with an argument. Internally the script is
    # saved as a list of tuples. The first value in the tuple is the name of
    # the command. Several commands are supported.
    #    write_verbatim() --> ('verb', <str>)
    #        Outputs the argument verbatim.
    #    write_account_entry() --> ('interp', <label>)
    #        Interpolates information from the account file into the output.
    #        The argument is the item to be interpolated (username, url, etc.)
    #    write_password() --> ('password')
    #        Outputs the password as a secret (the writer does its best to keep
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
    def __init__(self, output, password, wait=60, logger=None):
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
        regex = re.compile(r'({\w+})')
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
        label_password = len(self.script) > 1

        # Attach color label to a value
        def highlight(label, value):
            return cursor.color(label.upper() + ': ', 'magenta') + value

        # Send output to stdout with the labels.
        def display_secret(label, secret):
            if self.wait:
                text = highlight(label, secret)
                try:
                    cursor.write(text)
                    sleep(self.wait)
                    cursor.clear()
                except KeyboardInterrupt:
                    cursor.clear()
            if label_password:
                print(highlight(label, secret))
            else:
                print(secret)

        # Execute the script
        for action in self.script:
            if action[0] == 'interp':
                value = self.password.account.get_field(action[1])
                if value:
                    if type(value) == list:
                        print(highlight(
                            action[1],
                            '\n    ' + ',\n    '.join(value)))
                    elif '\n' in value:
                        print(highlight(
                            action[1],
                            '\n' + indent(value.strip(), '    ')))
                    else:
                        print(highlight(action[1], value.rstrip()))
            elif action[0] == 'password':
                display_secret(
                    'PASSWORD',
                    self.password.generate_password()
                )
            elif action[0] == 'question':
                questions = self.password.account.get_field(
                    'security questions')
                if questions:
                    if action[1] is None:
                        for index, question in enumerate(questions):
                            print(highlight('QUESTION %d' % index, question))
                    else:
                        try:
                            print(highlight(
                                'QUESTION %d' % action[1],
                                questions[action[1]]))
                        except IndexError:
                            print(highlight(
                                'QUESTION %d' % action[1],
                                '<not available>'))
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
                if type(value) == list:
                    lines += [', '.join(value)]
                elif value:
                    lines += [value.rstrip()]
                else:
                    lines += ['<%s unknown>' % action[1]]
            elif action[0] == 'password':
                lines += [self.password.generate_password()]
            elif action[0] == 'question':
                questions = self.password.account.get_field(
                    'security questions')
                if action[1] is None:
                    for index, question in enumerate(questions):
                        lines += ['question %d: %s' % (index, question)]
                else:
                    try:
                        lines += ['question %d: %s' % (
                            action[1], questions[action[1]])]
                    except IndexError:
                        lines += ['question %d: <not available>' % action[1]]
            elif action[0] == 'answer':
                question, answer = self.password.generate_answer(action[1])
                if answer:
                    lines += [answer]
            else:
                raise NotImplementedError
        text = '\n'.join(lines)
        log('Writing to clipboard.', self.logger)

        # Use 'xsel' to put the information on the clipboard.
        # This represents a vunerability, if someone were to replace xsel they
        # could sell my passwords. This is why I use an absolute path. I tried
        # to access the clipboard directly using GTK but I cannot get the code
        # to work.
        try:
            pipe('%s -b -i' % XSEL, text)
        except ExecuteError as err:
            error(err.message, self.logger)
        try:
            sleep(self.wait)
        except KeyboardInterrupt:
            pass
        try:
            execute("%s -b -c" % XSEL)
        except ExecuteError as err:
            error(err.message, self.logger)

        # Use Gobject Introspection (GTK) to put the information on the
        # clipboard (for some reason I cannot get this to work).
        #try:
        #    from gi.repository import Gtk, Gdk
        #
        #    clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        #    clipboard.set_text(text, len(text))
        #    clipboard.store()
        #    sleep(self.wait)
        #    clipboard.clear()
        #except ImportError:
        #    error('Clipboard is not supported.')

    # Process output to autotype {{{3
    def _process_output_to_autotype(self):
        # Mimic a keyboard to send output to the active window.

        def autotype(text):
            # Use 'xdotool' to mimic the keyboard.
            # For reasons I do not understand, sending a newline to xdotool
            # does not always result in a newline coming out. So separate out
            # the newlines and send them using as an explicit 'key' stroke.
            regex = re.compile(r'(\n)')
            segments = regex.split(text)
            try:
                for segment in segments:
                    if segment == '\n':
                        execute('%s key Return' % XDOTOOL)
                    elif segment != '':
                        # send text to xdotool through stdin so it cannot be
                        # seen with ps
                        pipe(
                            '%s -' % XDOTOOL,
                            'getactivewindow type "%s"' % segment)
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
                if type(value) == list:
                    value = ', '.join(value)
                elif value:
                    value = value.rstrip()
                else:
                    value = '<%s unknown>' % action[1]
                text += [value]
                scrubbed += [value]
            elif action[0] == 'password':
                text += [self.password.generate_password()]
                scrubbed += ['<<password>>']
            elif action[0] == 'question':
                questions = self.password.account.get_field(
                    'security questions')
                if action[1] is None:
                    for index, question in enumerate(questions):
                        value = 'question %d: %s' % (index, question)
                else:
                    try:
                        value = 'question %d: %s' % (
                            action[1], questions[action[1]])
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
    def __init__(self, settings_dir=None, init=None, logger=None):
        """Arguments:
           settings_dir
               Path to the settings directory. Generally only specified when
               testing.
           init
               GPG ID. When present, the settings directory is assumed not to
               exist and so is created using the specified ID.
           logger: Object that provides display(msg), log(msg), and error(msg)
               methods:
                   display() is called when a message is to be sent to the user
                   log() is called when a message is to be logged
                   exit() is called when an error has occurred.
        """

        if not settings_dir:
            settings_dir = DEFAULT_SETTINGS_DIR
        self.settings_dir = expand_path(settings_dir)
        if not logger:
            logger = Logging()
        self.logger = logger
        self.accounts_path = make_path(self.settings_dir, ACCOUNTS_FILENAME)

        # Get the dictionary
        self.dictionary = Dictionary(
            DICTIONARY_FILENAME, self.settings_dir, logger)

        # Activate GPG
        self.gpg = gnupg.GPG()

        # Process master password file
        self.master_password_path = make_path(
            self.settings_dir, MASTER_PASSWORD_FILENAME)
        if init:
            self._create_initial_settings_files(gpg_id=init)
        self.master_password = MasterPassword(
            self.master_password_path, self.dictionary, self.gpg, self.logger)
        try:
            accounts_path = self.master_password.data['accounts']
            self.accounts_path = make_path(self.settings_dir, accounts_path)
        except KeyError:
            pass

    # Create initial settings files {{{2
    # Will create initial versions of the master password file and the accounts
    # file, but only if they do not already exist. The master password file is
    # encrypted with the GPG ID given on the command line, which should be the
    # users.
    def _create_initial_settings_files(self, gpg_id):
        """Create initial version of settings files for the user.

           Arguments:
           Requires user's GPG ID as the only argument.
        """

        def create_file(filename, contents, encrypt=False):
            if encrypt:
                encrypted = self.gpg.encrypt(
                    contents, gpg_id, always_trust=True, armor=True
                )
                if not encrypted.ok:
                    error(
                        "%s: unable to encrypt.\n%s" % (
                            filename, encrypted.stderr),
                        self.logger)
                contents = str(encrypted)
            if is_file(filename):
                display("%s: already exists." % filename, self.logger)
            else:
                try:
                    with open(filename, 'w') as file:
                        file.write(contents)
                    os.chmod(filename, 0o600)
                    display("%s: created." % filename, self.logger)
                except IOError as err:
                    error(
                        '%s: %s.' % (err.filename, err.strerror), self.logger)

        # Generate a random long string to act as the default password
        def generate_random_string():
            def partition(bytestr):
                for each in list(bytestr):
                    yield each

            digest = os.urandom(64)
            import string
            alphabet = (
                string.ascii_letters + string.digits + string.punctuation)
            password = ''
            for index in partition(digest):
                password += alphabet[index % len(alphabet)]
            return password

        mkdir(self.settings_dir)
        if self.settings_dir == expand_path(DEFAULT_SETTINGS_DIR):
            default_password = generate_random_string()
        else:
            # if settings_dir is not the DEFAULT_SETTINGS_DIR, then this is
            # most probably a test, in which case we do not want to use a
            # random password as it would cause the test results to vary.
            default_password = '<< test pass phrase -- do not use >>'
        create_file(
            self.master_password_path,
            MASTER_PASSWORD_FILE_INITIAL_CONTENTS % (
                self.dictionary.hash, SECRETS_SHA1, CHARSETS_SHA1,
                ACCOUNTS_FILENAME, default_password),
            encrypt=True)
        create_file(
            self.accounts_path,
            ACCOUNTS_FILE_INITIAL_CONTENTS % (
                make_path(self.settings_dir, LOG_FILENAME),
                make_path(self.settings_dir, ARCHIVE_FILENAME),
                gpg_id),
            encrypt=(get_extension(self.accounts_path) in ['gpg', 'asc']))

    # Open the accounts file {{{2
    def read_accounts(self, template=DEFAULT_TEMPLATE):
        """Read accounts file.

           Required before secrets can be generated or accounts can be queried.
           Arguments:
           template:
               The template to be used if one is not found in the account.
        """
        accounts = Accounts(
            self.accounts_path, self.logger, self.gpg, template)
        self.accounts = accounts
        self.all_templates = accounts.all_templates
        self.all_accounts = accounts.all_accounts
        self.find_accounts = accounts.find_accounts
        self.search_accounts = accounts.search_accounts
        self.logger.set_logfile(accounts.get_log_file())

    # Get account {{{2
    def get_account(self, account_id):
        """Activate and return an account."""
        account = self.accounts.get_account(account_id)
        self.account = account
        log('Using account: %s' % account.get_id(), self.logger)
        self.master_password.set_master_password(account)
        return account

    # Generate password or answer {{{2
    def generate_password(self, account=None):
        """Produce a password or passphrase and give it to the user."""
        return self.master_password.generate_password(
            account if account else self.account)

    def generate_answer(self, question_number, account=None):
        """Produce an answer and give it to the user."""
        return self.master_password.generate_answer(
            account if account else self.account, question_number)

    # Print changed secrets {{{2
    def print_changed_secrets(self):
        """Identify updated secrets

           Inform the user of any secrets that have changes since they have
           been archived.
        """
        try:
            import yaml
        except ImportError:
            error('archive feature requires yaml, which is not available.', self.logger)

        gpg = gnupg.GPG()
        filename = expand_path(self.accounts.get_archive_file())
        try:
            with open(filename, 'rb') as f:
                encrypted_secrets = f.read()
        except IOError as err:
            error('%s: %s.' % (err.filename, err.strerror), self.logger)

        unencrypted_secrets = str(gpg.decrypt(encrypted_secrets))
        archived_secrets = yaml.load(unencrypted_secrets)

        # Look for changes in the accounts
        archived_ids = set(archived_secrets.keys())
        current_ids = set(list(self.all_accounts()))
        new_ids = current_ids - archived_ids
        deleted_ids = archived_ids - current_ids
        if new_ids:
            display(
                "NEW ACCOUNTS:\n    %s" % '\n    '.join(new_ids),
                self.logger)
        else:
            log("    No new accounts.", self.logger)
        if deleted_ids:
            display(
                "DELETED ACCOUNTS:\n    %s" % '\n    '.join(deleted_ids),
                self.logger)
        else:
            log("    No deleted accounts.", self.logger)

        # Loop through the accounts, and compare the secrets
        for account_id in self.all_accounts():
            questions = []
            account = self.get_account(account_id)
            password = self.generate_password(account)
            for i in account.get_security_questions():
                questions += [list(self.generate_answer(i, account))]
            if account_id in archived_secrets:
                # check that password is unchanged
                if password != archived_secrets[account_id]['password']:
                    display("PASSWORD DIFFERS: %s" % account_id, self.logger)
                else:
                    log("    Password matches.", self.logger)

                # check that number of questions is unchanged
                archived_questions = archived_secrets[account_id]['questions']
                if len(questions) != len(archived_questions):
                    display(
                        ' '.join([
                            "NUMBER OF SECURITY QUESTIONS CHANGED:",
                            "%s (was %d, is now %d)" % (
                                account_id,
                                len(archived_questions), len(questions))]),
                        self.logger)
                else:
                    log(
                        "    Number of questions match (%d)." % (
                            len(questions)),
                        self.logger)

                    # check that questions and answers are unchanged
                    pairs = zip(archived_questions, questions)
                    for i, (archived, new) in enumerate(pairs):
                        if archived[0] != new[0]:
                            display(
                                "QUESTION %d DIFFERS: %s (%s -> %s)." % (
                                    i, account_id, archived[0], new[0]),
                                self.logger)
                        else:
                            log(
                                "    Question %d matches (%s)." % (i, new[0]),
                                self.logger)
                        if archived[1] != new[1]:
                            display(
                                "ANSWER TO QUESTION %d DIFFERS: %s (%s)." % (
                                i, account_id, new[0]), self.logger)
                        else:
                            log(
                                "    Answer %d matches (%s)." % (i, new[0]),
                                self.logger)

    # Archive secrets {{{2
    def archive_secrets(self):
        """Archive secrets

           Save all secrets to the archive file.
        """
        try:
            import yaml
        except ImportError:
            error('archive feature requires yaml, which is not available.', self.logger)

        gpg = gnupg.GPG()
        # Loop through accounts saving passwords and questions
        all_secrets = {}
        for account_id in self.all_accounts():
            questions = []
            account = self.get_account(account_id)
            password = self.generate_password(account)
            log("    Saving password.", self.logger)
            for question in account.get_security_questions():
                # convert the result to a list rather than leaving it a tuple
                # because tuples are formatted oddly in yaml
                questions += [list(self.generate_answer(question, account))]
                log(
                    "    Saving question (%s) and its answer." % question,
                    self.logger)
            all_secrets[account_id] = {
                'password': password,
                'questions': questions
            }

        # Convert results to yaml archive
        unencrypted_secrets = yaml.dump(all_secrets)

        # Encrypt and save yaml archive
        gpg = gnupg.GPG()
        gpg_id = self.accounts.get_gpg_id()
        encrypted_secrets = gpg.encrypt(unencrypted_secrets, gpg_id)
        filename = expand_path(self.accounts.get_archive_file())
        try:
            with open(filename, 'w') as f:
                f.write(str(encrypted_secrets))
            os.chmod(filename, 0o600)
        except IOError as err:
            error('%s: %s.' % (err.filename, err.strerror), self.logger)


# PasswordError class {{{1
class PasswordError(Exception):
    def __init__(self, message):
        self.message = message

# Main {{{1
if __name__ == "__main__":
    cmd_line = CommandLine(sys.argv)
    try:
        with Logging(argv=sys.argv) as logging:
            password = Password(logger=logging, init=cmd_line.init)
            if cmd_line.init:
                terminate(logging)

            # Open the accounts file
            password.read_accounts(cmd_line.template)

            # If requested, list the available templates and then exit
            if cmd_line.list:
                display(
                    "MASTER PASSWORDS:\n   " + '\n   '.join(
                        sorted(password.master_password.password_names())),
                    logging)
                display(
                    "\nTEMPLATES:\n   " + '\n   '.join(
                        sorted(password.all_templates())),
                    logging)
                terminate(logging)

            # If requested, search the account database and exit after printing
            # results
            def print_search_results(search_term, search_func):
                to_print = []
                for acct, aliases in search_func(search_term):
                    aliases = ' (%s)' % (', '.join(aliases)) if aliases else ''
                    to_print += [acct + aliases]
                display(search_term + ':', logging)
                display('   ' + ('\n   '.join(sorted(to_print))), logging)

            if cmd_line.find:
                print_search_results(cmd_line.find, password.find_accounts)
                terminate(logging)

            if cmd_line.search:
                print_search_results(cmd_line.search, password.search_accounts)
                terminate(logging)

            if cmd_line.changed:
                password.print_changed_secrets()
                terminate(logging)
            if cmd_line.archive:
                password.archive_secrets()
                terminate(logging)

            # Select the requested account
            password.get_account(cmd_line.account)

            # Create the secrets writer
            style = 'c' if cmd_line.clipboard else (
                't' if cmd_line.autotype else 's')
            writer = PasswordWriter(style, password, cmd_line.wait, logging)

            # Process the users output requests
            if cmd_line.autotype:
                writer.write_autotype()
            else:
                if cmd_line.username or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('username')
                if cmd_line.account_number or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('account')
                if cmd_line.email or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('email')
                if cmd_line.url or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('url')
                if cmd_line.remarks or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('remarks')
                if cmd_line.info or cmd_line.all:
                    writer.write_question()
                if cmd_line.question is not None:
                    writer.write_answer(cmd_line.question)
                if cmd_line.password or cmd_line.all or writer.is_empty():
                    writer.write_password()

            # Output everything that the user requested.
            writer.process_output()
            terminate(logging)
    except PasswordError as err:
        sys.exit('%s: %s' % (cmd_line.name_as_invoked(), err.message))
    except KeyboardInterrupt:
        sys.exit('Killed by user')
