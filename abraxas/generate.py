# Abraxas Password Generator
#
# The password generator.
#
# Copyright (C) 2013-14 Kenneth S. Kundert and Kale Kundert

# License (fold)
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

# Imports (fold)
from __future__ import print_function, division
from fileutils import (
    makePath as make_path,
    getTail as get_tail,
    getHead as get_head,
    getExt as get_extension,
    isFile as is_file,
    expandPath as expand_path,
    mkdir, exists,
)
from abraxas.logger import Logging
from abraxas.dictionary import Dictionary
from abraxas.master import _MasterPassword
from abraxas.accounts import _Accounts
from abraxas.prefs import (
    DEFAULT_ACCOUNTS_FILENAME,
    DEFAULT_SETTINGS_DIR,
    DEFAULT_TEMPLATE,
    DICTIONARY_FILENAME,
    GPG_BINARY,
    MASTER_PASSWORD_FILENAME,
    MASTER_PASSWORD_FILE_INITIAL_CONTENTS,
    ACCOUNTS_FILE_INITIAL_CONTENTS,
    SECRETS_SHA1, CHARSETS_SHA1,
    DEFAULT_LOG_FILENAME, DEFAULT_ARCHIVE_FILENAME
)
import argparse
import gnupg
import hashlib
import os


class PasswordGenerator:
    """
    Abraxas Password Generator

    Primary class for Abraxas Password Generator.
    """

    def __init__(
        self, settings_dir=None, init=None, logger=None, gpg_home=None,
        stateless=False
    ):
        """
        Arguments:
        settings_dir (string)
               Path to the settings directory. Generally only specified when
               testing.
        init (string)
               User's GPG ID. When present, the settings directory is assumed
               not to exist and so is created using the specified ID.
        logger (object)
            Instance of class that provides display(), log(), debug(),
            error(), terminate() and set_logfile() methods:

            display(msg) is called when a message is to be sent to the user.
            log(msg) is called when a message is only to be logged.
            debug(msg) is called for debugging messages.
            error(msg) is called when an error has occurred, should not return.
            terminate() is called to indicate program has terminated normally.
            set_logfile(logfile, gpg, gpg_id) is called to specify
                information about the logfile, in particular, the path to
                the logfile, a gnupg encryption object, and the GPG ID.
                The last two must be specified if the logfile has an
                encryption extension (.gpg or .asc).

        gpg_home (string)
            Path to desired home directory for gpg.
        stateless (bool)
            Boolean that indicates that Abraxas should operate without 
            accessing the user's master password and accounts files.
        """

        if not settings_dir:
            settings_dir = DEFAULT_SETTINGS_DIR
        self.settings_dir = expand_path(settings_dir)
        if not logger:
            logger = Logging()
        self.logger = logger
        self.stateless = stateless
        self.accounts_path = make_path(
            self.settings_dir, DEFAULT_ACCOUNTS_FILENAME)

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
        self.master_password = _MasterPassword(
            self.master_password_path,
            self.dictionary,
            self.gpg,
            self.logger,
            stateless)
        try:
            path = self.master_password.data['accounts']
            if path:
                self.accounts_path = make_path(self.settings_dir, path)
        except KeyError:
            pass

    def _create_initial_settings_files(self, gpg_id):
        """
        Create initial version of settings files for the user (PRIVATE)

        Will create initial versions of the master password file and the 
        accounts file, but only if they do not already exist. The master 
        password file is encrypted with the GPG ID given on the command line, 
        which should be the users.

        Arguments:
        Requires user's GPG ID (string) as the only argument.
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

        def generate_random_string():
            # Generate a random long string to act as the default password

            from string import ascii_letters, digits, punctuation
            import random
            # Create alphabet from letters, digits, and punctuation, but 
            # replace double quote with a space so password can be safely 
            # represented as a double-quoted string.
            alphabet = (ascii_letters + digits + punctuation).replace('"', ' ')

            rand = random.SystemRandom()
            password = ''
            for i in range(64):
                password += rand.choice(alphabet)
            return password

        mkdir(self.settings_dir)
        default_password = generate_random_string()
        if self.settings_dir != expand_path(DEFAULT_SETTINGS_DIR):
            # If settings_dir is not the DEFAULT_SETTINGS_DIR, then this is
            # probably a test, in which case we do not want to use a
            # random password as it would cause the test results to vary.
            # Still want to generate the random string so that code gets
            # tested. It has been the source of trouble in the past.
            default_password = '<< test pass phrase -- do not use >>'
        create_file(
            self.master_password_path,
            MASTER_PASSWORD_FILE_INITIAL_CONTENTS % (
                self.dictionary.hash, SECRETS_SHA1, CHARSETS_SHA1,
                DEFAULT_ACCOUNTS_FILENAME, default_password),
            encrypt=True)
        create_file(
            self.accounts_path,
            ACCOUNTS_FILE_INITIAL_CONTENTS % (
                make_path(self.settings_dir, DEFAULT_LOG_FILENAME),
                make_path(self.settings_dir, DEFAULT_ARCHIVE_FILENAME),
                gpg_id),
            encrypt=(get_extension(self.accounts_path) in ['gpg', 'asc']))

    def read_accounts(self, template=DEFAULT_TEMPLATE):
        """
        Read accounts file.

        Required before secrets can be generated or accounts can be queried.

        Arguments:
        template (string)
            The template to be used if one is not found in the account.
        """
        accounts = _Accounts(
            self.accounts_path, self.logger, self.gpg, template, self.stateless
        )
        self.accounts = accounts
        self.all_templates = accounts.all_templates
        self.all_accounts = accounts.all_accounts
        self.find_accounts = accounts.find_accounts
        self.search_accounts = accounts.search_accounts
        if not self.stateless:
            self.logger.set_logfile(
                accounts.get_log_file(),
                accounts.gpg,
                accounts.get_gpg_id())

    def get_account(self, account_id, quiet=False):
        """
        Activate and return an account.

        Arguments:
        account_id (string)
            The account id or alias.
        quiet (bool)
            If true, the use of the account is only noted in the log file if
            DEBUG is true. This is generally set when archiving so that we do
            not leak the names of all available accounts.

        Returns:
            Account object.
        """
        account = self.accounts.get_account(account_id)
        self.account = account
        if quiet:
            self.logger.debug('Using account: %s' % account.get_id())
        else:
            self.logger.log('Using account: %s' % account.get_id())
        return account

    def generate_password(self, account=None, master_password=None):
        """
        Generate and return a password or passphrase.

        Arguments:
        account (object)
            Account object.
        master_password (string)
            Use to override the master password associated with the account.
            If the account does not have a master password, or if there is no
            account, the program will interactively request if from the user. 
            So this argument is generally not needed and only used when testing 
            the program.

        Returns:
            The desired password or passphrase (string).
        """
        return self.master_password.generate_password(
            account if account else self.account, master_password)

    def generate_answer(self, question, account=None):
        """
        Generate and return an answer to a particular question.

        Arguments:
        account (object)
            Account object.
        question (string or integer)
            Specifies which question is being asked. May either be the question
            text (a string) or it may be an index into the list of questions in
            the account (an integer).

        Returns:
            The question text and the corresponding answer (tuple of strings).
        """
        return self.master_password.generate_answer(
            account if account else self.account, question)

    def print_changed_secrets(self):
        """
        Identify updated secrets

        Inform the user of any secrets that have changed since they have been
        archived.
        """
        self.logger.log("Print changed secrets.")
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
            self.logger.log("No new accounts.")
        if deleted_ids:
            self.logger.display(
                "DELETED ACCOUNTS:\n    %s" % '\n    '.join(deleted_ids))
        else:
            self.logger.log("No deleted accounts.")

        # Loop through the accounts, and compare the secrets
        accounts_with_password_diffs = []
        accounts_with_question_diffs = []
        for account_id in self.all_accounts():
            questions = []
            account = self.get_account(account_id, quiet=True)
            password = self.generate_password(account)
            for i in account.get_security_questions():
                questions += [list(self.generate_answer(i, account))]
            if account_id in archived_secrets:
                # check that password is unchanged
                if password != archived_secrets[account_id]['password']:
                    accounts_with_password_diffs += [account_id]
                    self.logger.display("PASSWORD DIFFERS: %s" % account_id)
                else:
                    self.logger.debug("    Password matches.")

                # check that number of questions is unchanged
                archived_questions = archived_secrets[account_id]['questions']
                if len(questions) != len(archived_questions):
                    accounts_with_question_diffs += [account_id]
                    self.logger.display(
                        ' '.join([
                            "NUMBER OF SECURITY QUESTIONS CHANGED:",
                            "%s (was %d, is now %d)" % (
                                account_id,
                                len(archived_questions), len(questions))]))
                else:
                    self.logger.debug(
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
                            self.logger.debug(
                                "    Question %d matches (%s)." % (i, new[0]))
                        if archived[1] != new[1]:
                            self.logger.display(
                                "ANSWER TO QUESTION %d DIFFERS: %s (%s)." % (
                                    i, account_id, new[0]))
                        else:
                            self.logger.debug(
                                "    Answer %d matches (%s)." % (i, new[0]))
        if accounts_with_password_diffs:
            self.logger.log(
                "Accounts with changed passwords:\n    %s" % ',\n    '.join(
                    accounts_with_password_diffs))
        else:
            self.logger.log("No accounts with changed passwords")
        if accounts_with_question_diffs:
            self.logger.log(
                "Accounts with changed questions:\n    %s" % ',\n    '.join(
                    accounts_with_question_diffs))
        else:
            self.logger.log("No accounts with changed questions")

    def archive_secrets(self):
        """
        Archive secrets

        Save all secrets to the archive file.
        """
        self.logger.log("Archive secrets.")
        try:
            import yaml
        except ImportError:
            self.logger.error(
                'archive feature requires yaml, which is not available.')

        # Loop through accounts saving passwords and questions
        all_secrets = {}
        for account_id in self.all_accounts():
            questions = []
            account = self.get_account(account_id, quiet=True)
            password = self.generate_password(account)
            self.logger.debug("    Saving password.")
            for question in account.get_security_questions():
                # convert the result to a list rather than leaving it a tuple
                # because tuples are formatted oddly in yaml
                questions += [list(self.generate_answer(question, account))]
                self.logger.debug(
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


class PasswordError(Exception):
    """Password Error

    Not actually used by Abraxas directly. Rather, it made available by Abraxas 
    to the user. If it is passed into the logger, Abraxas will generate 
    PasswordError exceptions when there is an error rather than printing error 
    messages directly to the user and exiting.
    """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

# vim: set sw=4 sts=4 et:
