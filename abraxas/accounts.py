# Abraxas Password Accounts
#
# Responsible for reading and managing the data from the user's accounts file.
#
# Copyright (C) 2013-14 Kenneth S. Kundert and Kale B. Kundert

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
from abraxas.prefs import (
    DEFAULT_SETTINGS_DIR, DEFAULT_ARCHIVE_FILENAME, DEFAULT_LOG_FILENAME,
    STRING_FIELDS, INTEGER_FIELDS, LIST_FIELDS, LIST_OR_STRING_FIELDS,
    ENUM_FIELDS, SEARCH_FIELDS, PREFER_HTTPS, ACCOUNTS_FILE_INITIAL_CONTENTS,
    XDOTOOL, DEFAULT_AUTOTYPE, TITLE_PATTERNS, URL_PATTERN
)
from fileutils import (
    exists, getExt as get_extension, makePath as make_path,
    getHead as get_head, execute, pipe, ExecuteError
)
import re
import sys
import fnmatch
import traceback


class _Accounts:
    """
    Abraxas Accounts

    Responsible for reading and managing the data from the user's accounts 
    file.
    """

    def __init__(self, path, logger, gpg, template=None, stateless=False):
        self.path = path
        self.logger = logger
        self.gpg = gpg
        self.stateless = stateless
        self.data = None

        if stateless:
            # Use initial accounts so that user has access to basic templates
            imported_data = {}
            exec(ACCOUNTS_FILE_INITIAL_CONTENTS, imported_data)
            self.accounts = imported_data['accounts']
        else:
            # Load the user's accounts file
            self.accounts = self._read_accounts_file()

        if template:
            self.template = self.accounts.get(template, {})
            if not self.template:
                logger.error("%s: template not found." % template)
        else:
            self.template = {}

        self._validate_accounts()
        self._create_aliases()

    def _validate_accounts(self):
        """Validate and repair each account"""
        logger = self.logger

        for ID in self.all_accounts(skip_templates=False):
            if type(ID) != str:
                logger.error('%s: account ID must be a string.' % ID)
            data = self.accounts[ID]

            # check the types of the data in the various fields
            for each in STRING_FIELDS:
                if type(data.get(each, '')) != str:
                    logger.display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                each, ID, data[each]),
                            "Expected string, ignoring."]))
                    del data[each]
            for each in INTEGER_FIELDS:
                if type(data.get(each, 0)) != int:
                    logger.display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                each, ID, data[each]),
                            "Expected integer, ignoring."]))
                    del data[each]
            for each in LIST_FIELDS:
                if type(data.get(each, [])) != list:
                    logger.display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                each, ID, data[each]),
                            "Expected list, ignoring."]))
                    del data[each]
            for each in LIST_OR_STRING_FIELDS:
                if (
                    type(data.get(each, [])) != list and
                    type(data.get(each, '')) != str
                ):
                    logger.display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                each, ID, data[each]),
                            "Expected string or list, ignoring."]))
                    del data[each]
            for key, values in ENUM_FIELDS.items():
                val = data.get(key, '')
                if (val and val not in values):
                    logger.display(
                        ' '.join([
                            "Invalid value for '%s' in %s account (%s)." % (
                                key, ID, data[key]),
                            "Expected one from: %s." % ', '.join(values),
                            "Ignored."]))
                    del data[key]

    def _create_aliases(self):
        """Create dictionary of aliases"""

        def addToAliases(ID, name):
            if name in self.aliases:
                self.logger.error(
                    ' '.join([
                        "Alias %s" % (name),
                        "from account %s" % (
                            ID if name != ID else self.aliases[name]),
                        "duplicates an account name or previous entry,",
                        "ignoring."]))
            else:
                self.aliases[name] = ID

        self.aliases = {}
        for ID in self.all_accounts(skip_templates=False):
            # add ID to the aliases and then add the actual aliases
            data = self.accounts[ID]
            addToAliases(ID, ID)
            for alias in data.get('aliases', []):
                addToAliases(ID, alias)

    def all_accounts(self, skip_templates=True):
        # Get a dictionary of all the fields for each account {{{2
        for ID in self.accounts:
            if skip_templates and ID[0] == '=':
                pass
            else:
                yield ID

    def get_fields(self, field):
        # Get a particular field from each account {{{2
        for ID, data in self.accounts.items():
            if field in data and data[field]:
                yield (ID, data[field])

    def _read_accounts_file(self):
        if not self.path:
            # There is no accounts file
            self.data = {}
            return self.data
        if not exists(self.path):
            # If file does not exist, look for encrypted versions
            for ext in ['gpg', 'asc']:
                new_path = '.'.join([self.path, ext])
                if exists(new_path):
                    self.path = new_path
                    break

        logger = self.logger
        accounts_data = {}
        try:
            if get_extension(self.path) in ['gpg', 'asc']:
                # Accounts file is GPG encrypted, decrypt it before loading
                with open(self.path, 'rb') as f:
                    decrypted = self.gpg.decrypt_file(f)
                    if not decrypted.ok:
                        logger.error("%s\n%s" % (
                            "%s: unable to decrypt." % (self.path),
                            decrypted.stderr))
                    code = compile(decrypted.data, self.path, 'exec')
                    exec(code, accounts_data)
            else:
                # Accounts file is not encrypted
                with open(self.path) as f:
                    code = compile(f.read(), self.path, 'exec')
                    exec(code, accounts_data)
            additional_accounts = accounts_data.get('additional_accounts', [])
            if type(additional_accounts) == str:
                additional_accounts = [additional_accounts]
            more_accounts = {}
            for each in additional_accounts:
                path = make_path(get_head(self.path), each)
                if get_extension(path) in ['gpg', 'asc']:
                    # Accounts file is GPG encrypted, decrypt it
                    try:
                        with open(path, 'rb') as f:
                            decrypted = self.gpg.decrypt_file(f)
                            if not decrypted.ok:
                                logger.error("%s\n%s" % (
                                    "%s: unable to decrypt." % (path),
                                    decrypted.stderr))
                            code = compile(decrypted.data, path, 'exec')
                            exec(code, more_accounts)
                    except IOError as err:
                        logger.error('%s: %s.' % (err.filename, err.strerror))
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
                    logger.display(
                        "%s: overrides existing accounts:\n    %s" % (
                            path, ',\n    '.join(sorted(keys_in_common))))
                elif keys_in_common:
                    logger.display("%s: overrides existing account: %s" % (
                        path, keys_in_common[0]))
                accounts_data['accounts'].update(more_accounts['accounts'])
        except IOError as err:
            logger.error('%s: %s.' % (err.filename, err.strerror))
        except SyntaxError as err:
            traceback.print_exc(0)
            sys.exit()
        self.data = accounts_data
        try:
            return accounts_data['accounts']
        except KeyError:
            logger.error(
                "%s: defective accounts file, 'accounts' not found." %
                    self.path
            )

    def get_log_file(self):
        return self.data.get(
            'log_file',
            make_path(DEFAULT_SETTINGS_DIR, DEFAULT_LOG_FILENAME))

    def get_archive_file(self):
        return self.data.get(
            'archive_file',
            make_path(DEFAULT_SETTINGS_DIR, DEFAULT_ARCHIVE_FILENAME))

    def get_gpg_id(self):
        try:
            return self.data['gpg_id']
        except KeyError:
            if self.data:
                self.logger.error(
                    "'gpg_id' missing from %s (see 'man 5 abraxas')." % (
                        self.path))
            return None

    def all_templates(self):
        # Iterate through  templates
        # Templates are accounts whose ID starts with =.
        for key in self.accounts:
            if key[0] == '=':
                yield key

    class Account:
        """
        Abraxas Account

        Responsible for holding all of the information for a particular 
        account.
        """

        def __init__(self, ID, data):
            self.ID = ID
            self.data = data

        def get_id(self):
            """Return account's ID."""
            return self.ID

        def get_data(self):
            """Return account's data."""
            return self.data

        def get_field(self, field, default=None):
            """
            Return value of a particular account field.

            Arguments:
            field (string)
                Name of desired field.
            default
                Value return if field is not present.
            """
            return self.data.get(field, default)

        def get_master(self, default):
            """Return name of account's master password."""
            return self.data.get('master', default)

        def get_version(self):
            """Return value of account's version field."""
            return self.data.get('version', '')

        def get_security_questions(self):
            """Return list account's security questions."""
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

    def get_account(self, account_id, level=0):
        if level > 20:
            self.logger.error(
                "%s: too many levels of templates, loop suspected." % (
                    account_id))

        def find_account_id():
            # Uses window title to perform account discovery
            logger = self.logger
            # Account ID was not given by the user.
            # Try to determine it from title of active window.
            # First get the title from the active window.
            try:
                status, title = pipe(
                    '%s getactivewindow getwindowname' % XDOTOOL)
            except ExecuteError as err:
                logger.error(str(err))
            title = title.strip()
            logger.log('Account Discovery ...')
            logger.log('Focused window title: %s' % title)

            # Look through fields in each account and see if any match.
            #   Title information is separated into components.
            #   Title matches if
            #   - title component matches if given
            #   - host component matches if given
            #   - email component matches if given
            #   - username component matches if given
            #   - account component matches if given
            #   But the following mismatches would invalidate:
            #   - any of the above, if given
            #   - protocol if given
            matches = set([])
            for pattern_name, pattern in TITLE_PATTERNS:
                logger.debug('Using title pattern: %s' % pattern_name)
                match = pattern.match(title)
                if match:
                    fields = match.groupdict()
                    logger.debug(
                        'Title components:\n    %s' % '\n    '.join([
                            '%s: %s' % (key, val)
                            for key, val in fields.items()
                        ])
                    )
                    required_protocol = None
                    for ID, account in self.accounts.items():
                        logger.debug('Trying account: %s' % ID)
                        windows = account.get('window', [])
                        if type(windows) == str:
                            windows = [windows]

                        match_found = False
                        reasons = []
                        for key in sorted(
                            fields.keys(), key=lambda x: x == 'protocol'
                        ):
                            # The above has a special sort that assures 
                            # protocol is processed last.
                            value = fields[key]
                            if key == 'title':
                                for each in windows:
                                    if fnmatch.fnmatch(value, each):
                                        match_found = True
                                        logger.debug('    title matches')
                                        reasons += ['title matches']
                                        break
                                else:
                                    if windows:
                                        logger.debug('    title mismatch')
                                        break
                            elif key == 'host':
                                urls = account.get('url', [])
                                if type(urls) == str:
                                    urls = [urls]
                                for url in urls:
                                    logger.debug('    account url: %s' % url)
                                    match = URL_PATTERN.match(url)
                                    if match:
                                        url = match.groupdict()
                                        logger.debug(
                                            '    url components:\n        %s' %
                                                '\n        '.join([
                                                    '%s: %s' % (k, v)
                                                    for k, v in url.items()
                                                ])
                                        )
                                    else:
                                        url = {}
                                    if fnmatch.fnmatch(
                                        value, url.get('host', '')
                                    ):
                                        match_found = True
                                        logger.debug('    host matches')
                                        reasons += ['host matches']
                                        required_protocol = url['protocol']
                                        if required_protocol:
                                            required_protocol = (
                                                required_protocol.lower())
                                        break
                                else:
                                    logger.debug('    host mismatch')
                                    break
                            elif key == 'username':
                                if key == account.get('username'):
                                    match_found = True
                                    logger.debug('    username matches')
                                    reasons += ['username matches']
                                else:
                                    logger.debug('    username mismatch')
                                    break
                            elif key == 'email':
                                if key == account.get('email'):
                                    logger.debug('    email matches')
                                    reasons += ['email matches']
                                    match_found = True
                                else:
                                    logger.debug('    email mismatch')
                                    break
                            elif key == 'account':
                                if key == account.get('account'):
                                    logger.debug('    account matches')
                                    reasons += ['account matches']
                                    match_found = True
                                else:
                                    logger.debug('    account mismatch')
                                    break
                            elif key == 'protocol':
                                if PREFER_HTTPS and not required_protocol:
                                    required_protocol = 'https'
                                if (
                                    required_protocol and
                                    value.lower() != required_protocol
                                ):
                                    logger.debug('    protocol mismatch')
                                    if match_found:
                                        if required_protocol == 'https':
                                            # this is the last test, and if 
                                            # a match is found but rejected 
                                            # because we are expecting https, 
                                            # warn the user that the page is 
                                            # not encrypted
                                            import abraxas.dialog
                                            abraxas.dialog.show_error_dialog(
                                                ' '.join([
                                                    "Account '%s' expects" % ID,
                                                    "page to be encrypted."
                                                ])
                                            )
                                    break
                        else:
                            if match_found:
                                logger.debug('    match!')
                                successful_reasons = reasons
                                matches.add(ID)
                            else:
                                logger.debug('    no fields to match')
                if matches:
                    # don't go through again if a match has already been found
                    break

            # Only a single match is allowed.
            logger.log(
                "Window title matches the following accounts: '%s'." % (
                    "' '".join(matches)))
            if len(matches) == 1:
                match = matches.pop()
                self.logger.log(
                    "'%s' account selected because %s." % (
                        match, ', '.join(successful_reasons)))
                return match
            elif matches:
                from abraxas.dialog import show_list_dialog
                account = show_list_dialog(sorted(matches))
                if account:
                    logger.log("User selected '%s' account." % account)
                    return account
            logger.error("Cannot determine desired account ID.")

        # Validate account_id
        if not account_id and not self.stateless:
            # User did not specify account ID on the command line.
            account_id = find_account_id()
        try:
            account_id = self.aliases[account_id]
            account = self.accounts[account_id]
        except KeyError:
            account = self.template
            if not self.stateless:
                self.logger.display(
                    "Warning: account '%s' not found." % account_id)

        # Get information from template
        template = account.get('template', None)
        if template:
            data = self.get_account(template, level=level+1).get_data()
        else:
            data = {}

        # Override template information with that from the account
        data.update(account)

        return _Accounts.Account(account_id, data)

    @staticmethod
    def _inID(pattern, ID):
        return bool(pattern.search(ID))

    @staticmethod
    def _inAliases(pattern, acct):
        for each in acct.get('aliases', ''):
            if pattern.search(each):
                return True
        return False

    def _inSearchField(self, pattern, ID, acct):
        for each in SEARCH_FIELDS:
            try:
                value = acct.get(each, '')
                if type(value) is list:
                    for every in value:
                        if pattern.search(every):
                            return True
                else:
                    if pattern.search(value):
                        return True
            except TypeError:
                self.logger.display(
                    "%s %s: field is of wrong type" % (ID, each))
        return False

    def find_accounts(self, target):
        """Iterate through accounts that match target.

        Look for target in account ID and aliases only.
        """

        pattern = re.compile(target, re.I)
        for ID in self.all_accounts():
            if (
                    self._inID(pattern, ID) or
                    self._inAliases(pattern, self.accounts[ID])):
                yield ID, self.accounts[ID].get('aliases', [])

    # Search accounts {{{2
    def search_accounts(self, target):
        """Iterate through accounts that match target.

        Look for target in account ID, aliases, and various fields.
        """
        pattern = re.compile(target, re.I)
        for ID in self.all_accounts():
            acct = self.accounts[ID]
            if (
                    self._inID(pattern, ID) or
                    self._inAliases(pattern, acct) or
                    self._inSearchField(pattern, ID, acct)):
                yield ID, self.accounts[ID].get('aliases', [])

# vim: set sw=4 sts=4 et:
