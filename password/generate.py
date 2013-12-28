# Password Generator
#
# The password generator.
#
# Copyright (C) 2013-14 Kenneth S. Kundert and Kale B. Kundert

# License {{{1
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

# Imports {{{1
from __future__ import print_function, division
from fileutils import (
    makePath as make_path,
    getTail as get_tail,
    getHead as get_head,
    getExt as get_extension,
    isFile as is_file,
    expandPath as expand_path,
    mkdir, exists,
    execute, pipe, ExecuteError
)
from password.logger import Logging
from password.dictionary import Dictionary
from password.master import MasterPassword
from password.writer import PasswordWriter
from password.accounts import Accounts
from password.prefs import (
    ACCOUNTS_FILENAME,
    DEFAULT_SETTINGS_DIR,
    DEFAULT_TEMPLATE,
    DICTIONARY_FILENAME,
    GPG_BINARY,
    MASTER_PASSWORD_FILENAME,
    MASTER_PASSWORD_FILE_INITIAL_CONTENTS,
    ACCOUNTS_FILE_INITIAL_CONTENTS,
    SECRETS_SHA1, CHARSETS_SHA1,
    LOG_FILENAME, ARCHIVE_FILENAME
)
from textwrap import dedent, wrap
import argparse
import gnupg
import hashlib
import traceback
import os

# PasswordGenerator class {{{1
class PasswordGenerator:
    """Password Generator"""
    # Constructor {{{2
    def __init__(self, settings_dir=None, init=None, logger=None, gpg_home=None):
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
                   log() is called when a message is only to be logged
                   error() is called when an error has occurred.
           gpg_home: path to desired home directory for gpg
        """

        if not settings_dir:
            settings_dir = DEFAULT_SETTINGS_DIR
        self.settings_dir = expand_path(settings_dir)
        if not logger:
            logger = Logging(exception=PasswordError)
        self.logger = logger
        self.accounts_path = make_path(self.settings_dir, ACCOUNTS_FILENAME)

        # Get the dictionary
        self.dictionary = Dictionary(
            DICTIONARY_FILENAME, self.settings_dir, logger)

        # Activate GPG
        gpg_args = {'gpgbinary': GPG_BINARY}
        if gpg_home:
            gpg_args.update({'gnupghome': gpg_home})
        self.gpg = gnupg.GPG(**gpg_args)

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
                    self.logger.error(
                        "%s: unable to encrypt.\n%s" % (
                            filename, encrypted.stderr))
                contents = str(encrypted)
            if is_file(filename):
                self.logger.display("%s: already exists." % filename)
            else:
                try:
                    with open(filename, 'w') as file:
                        file.write(contents)
                    os.chmod(filename, 0o600)
                    self.logger.display("%s: created." % filename)
                except IOError as err:
                    self.logger.error('%s: %s.' % (err.filename, err.strerror))

        # Generate a random long string to act as the default password
        def generate_random_string():
            def partition(bytestr):
                for each in list(bytestr):
                    yield each

            digest = os.urandom(64)
            from string import ascii_letters, digits, punctuation
            alphabet = (ascii_letters + digits + punctuation)
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
        self.logger.set_logfile(
            accounts.get_log_file(),
            accounts.gpg,
            accounts.get_gpg_id())

    # Get account {{{2
    def get_account(self, account_id):
        """Activate and return an account."""
        account = self.accounts.get_account(account_id)
        self.account = account
        self.logger.log('Using account: %s' % account.get_id())
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
            self.logger.error(
                'archive feature requires yaml, which is not available.')

        filename = expand_path(self.accounts.get_archive_file())
        try:
            with open(filename, 'rb') as f:
                encrypted_secrets = f.read()
        except IOError as err:
            self.logger.error('%s: %s.' % (err.filename, err.strerror))

        unencrypted_secrets = str(self.gpg.decrypt(encrypted_secrets))
        archived_secrets = yaml.load(unencrypted_secrets)

        # Look for changes in the accounts
        archived_ids = set(archived_secrets.keys())
        current_ids = set(list(self.all_accounts()))
        new_ids = current_ids - archived_ids
        deleted_ids = archived_ids - current_ids
        if new_ids:
            self.logger.display(
                "NEW ACCOUNTS:\n    %s" % '\n    '.join(new_ids))
        else:
            self.logger.log("    No new accounts.")
        if deleted_ids:
            self.logger.display(
                "DELETED ACCOUNTS:\n    %s" % '\n    '.join(deleted_ids))
        else:
            self.logger.log("    No deleted accounts.")

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
                    self.logger.display("PASSWORD DIFFERS: %s" % account_id)
                else:
                    self.logger.log("    Password matches.")

                # check that number of questions is unchanged
                archived_questions = archived_secrets[account_id]['questions']
                if len(questions) != len(archived_questions):
                    self.logger.display(
                        ' '.join([
                            "NUMBER OF SECURITY QUESTIONS CHANGED:",
                            "%s (was %d, is now %d)" % (
                                account_id,
                                len(archived_questions), len(questions))]))
                else:
                    self.logger.log(
                        "    Number of questions match (%d)." % (
                            len(questions)))

                    # check that questions and answers are unchanged
                    pairs = zip(archived_questions, questions)
                    for i, (archived, new) in enumerate(pairs):
                        if archived[0] != new[0]:
                            self.logger.display(
                                "QUESTION %d DIFFERS: %s (%s -> %s)." % (
                                    i, account_id, archived[0], new[0]))
                        else:
                            self.logger.log(
                                "    Question %d matches (%s)." % (i, new[0]))
                        if archived[1] != new[1]:
                            self.logger.display(
                                "ANSWER TO QUESTION %d DIFFERS: %s (%s)." % (
                                i, account_id, new[0]))
                        else:
                            self.logger.log(
                                "    Answer %d matches (%s)." % (i, new[0]))

    # Archive secrets {{{2
    def archive_secrets(self):
        """Archive secrets

           Save all secrets to the archive file.
        """
        try:
            import yaml
        except ImportError:
            self.logger.error(
                'archive feature requires yaml, which is not available.')

        # Loop through accounts saving passwords and questions
        all_secrets = {}
        for account_id in self.all_accounts():
            questions = []
            account = self.get_account(account_id)
            password = self.generate_password(account)
            self.logger.log("    Saving password.")
            for question in account.get_security_questions():
                # convert the result to a list rather than leaving it a tuple
                # because tuples are formatted oddly in yaml
                questions += [list(self.generate_answer(question, account))]
                self.logger.log(
                    "    Saving question (%s) and its answer." % question)
            all_secrets[account_id] = {
                'password': password,
                'questions': questions
            }

        # Convert results to yaml archive
        unencrypted_secrets = yaml.dump(all_secrets)

        # Encrypt and save yaml archive
        gpg_id = self.accounts.get_gpg_id()
        encrypted_secrets = self.gpg.encrypt(unencrypted_secrets, gpg_id)
        filename = expand_path(self.accounts.get_archive_file())
        try:
            with open(filename, 'w') as f:
                f.write(str(encrypted_secrets))
            os.chmod(filename, 0o600)
        except IOError as err:
            self.logger.error('%s: %s.' % (err.filename, err.strerror))


# PasswordError class {{{1
class PasswordError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

