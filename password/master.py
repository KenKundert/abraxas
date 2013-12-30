# Master Password
#
# Responsible for reading and managing the data from the master password file.
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
import password.secrets as secrets
import hashlib
from fileutils import (
    makePath as make_path,
    getHead as get_head,
    getExt as get_extension,
)
from textwrap import wrap
import sys
import traceback

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
            lambda text: logger.display(text))
        self.password = secrets.Password(
            lambda text: logger.display(text))
        self._validate_assumptions()

    # Read master password file {{{2
    def _read_master_password_file(self):
        data = {}
        try:
            with open(self.path, 'rb') as f:
                decrypted = self.gpg.decrypt_file(f)
                if not decrypted.ok:
                    self.logger.error("%s\n%s" % (
                        "%s: unable to decrypt." % (self.path),
                        decrypted.stderr
                    ))
                code = compile(decrypted.data, self.path, 'exec')
                exec(code, data)
        except IOError as err:
            self.logger.error('%s: %s.' % (err.filename, err.strerror))
        except SyntaxError as err:
            traceback.print_exc(0)
            sys.exit()
        for ID in data.get('passwords', {}):
            if type(ID) != str:
                self.logger.error(
                    '%s: master password ID must be a string.' % ID)

        # Open additional master password files
        additional_password_files = data.get(
            'additional_master_password_files', [])
        if type(additional_password_files) == str:
            additional_password_files = additional_password_files.split()
        more_data = {}
        for each in additional_password_files:
            path = make_path(get_head(self.path), each)
            if get_extension(path) in ['gpg', 'asc']:
                # File is GPG encrypted, decrypt it
                try:
                    with open(path, 'rb') as f:
                        decrypted = self.gpg.decrypt_file(f)
                        if not decrypted.ok:
                            self.logger.error("%s\n%s" % (
                                "%s: unable to decrypt." % (path),
                                decrypted.stderr
                            ))
                        code = compile(decrypted.data, path, 'exec')
                        exec(code, more_data)
                except IOError as err:
                    self.logger.error('%s: %s.' % (err.filename, err.strerror))
            else:
                self.logger.error(
                    "%s: must have .gpg or .asc extension" % (path))

            # Check for duplicate master passwords
            existing_passwords = set(data.get('passwords', {}).keys())
            new_passwords = set(more_data.get('passwords', {}).keys())
            keys_in_common = sorted(
                existing_passwords.intersection(new_passwords))
            if keys_in_common:
                self.logger.display(
                    "%s: overrides existing password:\n    %s" % (
                        path, ',\n    '.join(sorted(keys_in_common))))
            data['passwords'].update(more_data.get('passwords', {}))

            # Check for duplicate passwords overrides
            existing_overrides = set(data['password_overrides'].keys())
            new_overrides = set(more_data['password_overrides'].keys())
            keys_in_common = sorted(
                existing_overrides.intersection(new_overrides))
            if keys_in_common:
                self.logger.display(
                    "%s: overrides existing password overrides:\n    %s" % (
                        path, ',\n    '.join(sorted(keys_in_common))))
            data['password_overrides'].update(more_data.get('password_overrides',{}))

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
                path = make_path(get_head(__file__), '..', each + '.py')
                try:
                    with open(path) as f:
                        contents = f.read()
                except IOError as err:
                    self.logger.error('%s: %s.' % (err.filename, err.strerror))
            hash = hashlib.sha1(contents.encode('utf-8')).hexdigest()
            if hash != self._get_field('%s_hash' % each):
                self.logger.display("Warning: '%s' has changed." % path)
                self.logger.display("    " + "\n    ".join(wrap(' '.join([
                    "This results in passwords that are inconsistent",
                    "with those created in the past."]))))

    # Get field {{{2
    def _get_field(self, key):
        try:
            return self.data[key]
        except KeyError:
            self.logger.error("%s: cannot find '%s'" % (self.path, key))

    # Set the master password {{{2
    # Get the master password associated with this account.
    # If there is none, use the default.
    # If there is no default, ask the user for a password.
    def get_master_password(self, account):
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

    # Generate an answer to a security question {{{2
    # Only use pass phrases as answers to security questions, not passwords.
    def generate_answer(self, account, question):
        # question may either be the question text (a string) or it may be an
        # index into the list of questions in the account (an integer)
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


