# Abraxas Master Password
#
# Responsible for reading and managing the data from the master password file.
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
import abraxas.secrets as secrets
import hashlib
from fileutils import (
    makePath as make_path,
    getHead as get_head,
    getExt as get_extension,
)
from abraxas.prefs import (
    DEFAULT_SETTINGS_DIR, MASTER_PASSWORD_FILENAME,
    DICTIONARY_SHA1, SECRETS_SHA1, CHARSETS_SHA1
)
from textwrap import wrap
import sys
import traceback


class _MasterPassword:
    """
    Master password class

    Responsible for reading and managing the data from the master password 
    file.
    """

    def __init__(self, path, dictionary, gpg, logger, stateless):
        self.path = path
        self.dictionary = dictionary
        self.gpg = gpg
        self.logger = logger
        self.stateless = stateless
        self.data = self._read_master_password_file()
        self.passphrase = secrets.Passphrase(
            lambda text: logger.display(text))
        self.password = secrets.Password(
            lambda text: logger.display(text))
        self._validate_assumptions()

    def _read_master_password_file(self):
        data = {
            'accounts': None,
            'passwords': {},
            'default_password': None,
            'password_overrides': {},
            'additional_master_password_files': [],
        }
        if not self.stateless:
            try:
                with open(self.path, 'rb') as f:
                    decrypted = self.gpg.decrypt_file(f)
                    if not decrypted.ok:
                        self.logger.error("%s" %
                            "%s: unable to decrypt." % (self.path),
                        )
                    code = compile(decrypted.data, self.path, 'exec')
                    exec(code, data)
            except IOError as err:
                self.logger.display(
                    'Warning: could not read master password file %s: %s.' % (
                        err.filename, err.strerror))
            except SyntaxError as err:
                traceback.print_exc(0)
                sys.exit()

        # assure that the keys on the master passwords are strings
        for ID in data.get('passwords', {}):
            if type(ID) != str:
                self.logger.error(
                    '%s: master password ID must be a string.' % ID)

        # Open additional master password files
        additional_password_files = data.get(
            'additional_master_password_files', [])
        if type(additional_password_files) == str:
            additional_password_files = [additional_password_files]
        for each in additional_password_files:
            more_data = {}
            path = make_path(get_head(self.path), each)
            if get_extension(path) in ['gpg', 'asc']:
                # File is GPG encrypted, decrypt it
                try:
                    with open(path, 'rb') as f:
                        decrypted = self.gpg.decrypt_file(f)
                        if not decrypted.ok:
                            self.logger.error("%s" %
                                "%s: unable to decrypt." % (path),
                            )
                            continue
                        code = compile(decrypted.data, path, 'exec')
                        exec(code, more_data)
                except IOError as err:
                    self.logger.display('%s: %s.  Ignored.' % (
                        err.filename, err.strerror
                    ))
                    continue
            else:
                self.logger.error(
                    "%s: must have .gpg or .asc extension" % (path))

            # Check for duplicate master passwords
            existing_names = set(data.get('passwords', {}).keys())
            new_passwords = more_data.get('passwords', {})
            new_names = set(new_passwords.keys())
            names_in_common = sorted(
                existing_names.intersection(new_names))
            if names_in_common:
                self.logger.display(
                    "%s: overrides existing password:\n    %s" % (
                        path, ',\n    '.join(sorted(names_in_common))))
            data['passwords'].update(new_passwords)

            # Check for duplicate passwords overrides
            existing_names = set(data['password_overrides'].keys())
            new_overrides = more_data.get('password_overrides', {})
            new_names = set(new_overrides.keys())
            names_in_common = sorted(
                existing_names.intersection(new_names))
            if names_in_common:
                self.logger.display(
                    "%s: overrides existing password overrides:\n    %s" % (
                        path, ',\n    '.join(sorted(names_in_common))))
            data['password_overrides'].update(new_overrides)

        return data

    def _validate_assumptions(self):
        # Check that dictionary has not changed.
        # If the master password file exists, then self.data['dict_hash'] will 
        # exist, and we will compare the current hash for the dictionary 
        # against that stored in the master password file, otherwise we will 
        # compare against the one present when the program was configured.
        self.dictionary.validate(self.data.get('dict_hash', DICTIONARY_SHA1))

        # Check that secrets.py and charset.py have not changed
        for each, sha1 in [
            ('secrets', SECRETS_SHA1),
            ('charsets', CHARSETS_SHA1)
        ]:
            path = make_path(get_head(__file__), each + '.py')
            try:
                with open(path) as f:
                    contents = f.read()
            except IOError as err:
                path = make_path(get_head(__file__), '..', each + '.py')
                try:
                    with open(path) as f:
                        contents = f.read()
                except IOError as err:
                    self.logger.error('%s: %s.' % (err.filename, err.strerror))
            hash = hashlib.sha1(contents.encode('utf-8')).hexdigest()
            # Check that file has not changed.
            # If the master password file exists, then self.data['%s_hash'] 
            # will exist, and we will compare the current hash for the file 
            # against that stored in the master password file, otherwise we 
            # will compare against the one present when the program was 
            # configured.
            if hash != self.data.get('%s_hash' % each, sha1):
                self.logger.display("Warning: '%s' has changed." % path)
                self.logger.display("    " + "\n    ".join(wrap(' '.join([
                    "This could result in passwords that are inconsistent",
                    "with those created in the past.",
                    'Update the corresponding hash in %s/%s to "%s".' % (
                        DEFAULT_SETTINGS_DIR, MASTER_PASSWORD_FILENAME, hash),
                    "Then use 'abraxas --changed' to assure that nothing has",
                    "changed."
                ]))))

    def _get_field(self, key):
        try:
            return self.data[key]
        except KeyError:
            self.logger.error("%s: cannot find '%s'" % (self.path, key))

    def get_master_password(self, account):
        """Get the master password associated with this account.

        If there is none, use the default.
        If there is no default, ask the user for a password.
        """
        passwords = self._get_field('passwords')
        default_password = self._get_field('default_password')

        # Get the master password for this account.
        if account:
            password_id = account.get_master(default_password)
        else:
            password_id = default_password
        if password_id:
            try:
                return passwords[password_id]
            except KeyError:
                self.logger.error(
                    '%s: master password not found.' % password_id)
        else:
            import getpass
            try:
                self.logger.display(
                    "Provide master password for account '%s'." % account.ID)
                master_password = getpass.getpass()
                if not master_password:
                    self.logger.display("Warning: Master password is empty.")
                return master_password
            except (EOFError, KeyboardInterrupt):
                sys.exit()

    def password_names(self):
        """Return a list that contains the name of the master passwords."""
        return self._get_field('passwords').keys()

    def generate_password(self, account, master_password=None):
        """Generate the password for the specified account

        Generally you should not need to pass in the master_password. This is
        only done for testing the stateless password generation.
        """
        try:
            return self.data['password_overrides'][account.get_id()]
        except KeyError:
            pass

        # Otherwise generate a pass phrase or a password as directed
        if not master_password:
            master_password = self.get_master_password(account)
        password_type = account.get_password_type()
        if password_type == 'words':
            return self.passphrase.generate(
                master_password, account, self.dictionary)
        elif password_type == 'chars':
            return self.password.generate(master_password, account)
        else:
            self.logger.error(
                "%s: unknown password type (expected 'words' or 'chars').")

    def generate_answer(self, account, question):
        """Generate an answer to a security question

        Question may either be the question text (a string) or it may be an
        index into the list of questions in the account (an integer).
        """
        # Configured to use only pass phrases as answers to security questions.
        # This is because people doing phone support will often simply ignore
        # those security questions that seem like gibberish to them.
        if type(question) == int:
            # question given as an index, convert it to the question text
            security_questions = account.get_security_questions()
            try:
                question = security_questions[question]
            except IndexError:
                self.logger.error(
                    'There is no security question #%s.' % question)
        master_password = self.get_master_password(account)
        answer = self.passphrase.generate(
            master_password, account, self.dictionary, question)
        return (question, answer)

# vim: set sw=4 sts=4 et:
