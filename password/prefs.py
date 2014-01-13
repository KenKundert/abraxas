# Password Generator
#
# Preferences.
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
from textwrap import dedent
import re

# Globals {{{1
# Filenames {{{2
DEFAULT_SETTINGS_DIR = '~/.config/pw'
MASTER_PASSWORD_FILENAME = 'master.gpg'
DEFAULT_ACCOUNTS_FILENAME = 'accounts'
    # accounts file will be encrypted if you add .gpg or .asc extension
DICTIONARY_FILENAME = 'words'
DEFAULT_LOG_FILENAME = 'log'
    # log file will be encrypted if you add .gpg or .asc extension
DEFAULT_ARCHIVE_FILENAME = 'archive.gpg'

# Defaults {{{2
DEFAULT_TEMPLATE = "=words"
DEFAULT_AUTOTYPE = "{username}{tab}{password}{return}"
# Use absolute paths for xdotool and xsel
# Makes it harder for someone to replace them so as to expose the secrets.

# Settings {{{2
LABEL_COLOR = 'yellow'
    # choose from normal, black, red, green, yellow, blue, magenta, cyan, white
LABEL_STYLE = 'normal'
    # choose from normal, bright, reverse, dim, underline, blink, reverse,
    # invisible (these need to be implemented by underlying terminal, and some
    # are not (such a blink and dim)
INITIAL_AUTOTYPE_DELAY = 0.5
DEBUG = False
    # Turns on the logging of extra information, but may expose sensitive
    # account information in the log file.
PREFER_HTTPS = True
    # When PREFER_HTTPS is true, pw will require the https protocol unless http
    # is explicitly specified in the url.
    # When PREFER_HTTPS is false, pw will allow the http protocol unless https
    # is explicitly specified in the url.

# Utility programs {{{2
XDOTOOL = '/usr/bin/xdotool'
XSEL = '/usr/bin/xsel'
GPG_BINARY = 'gpg2'
ZENITY = 'zenity'

# Signatures {{{2
# These signatures must be the sha1 signatures for the corresponding files
# Regenerate them with 'sha1sum <filename>'
# These are used in creating the initial master password file.
SECRETS_SHA1 = "bb7811863130f42cee268e85430f28ac888148c5"
CHARSETS_SHA1 = "dab48b2103ebde97f78cfebd15cc1e66d6af6ed0"

# Browsers {{{2
# Associate a command with a browser key.
# The command must contain a single %s, which is replaced with URL.
BROWSERS = {
    'f': 'firefox -new-tab %s > /dev/null',
    'v': 'vimprobable2 %s',
}
DEFAULT_BROWSER = 'f'

# Account Recognition {{{2
# Title Recognition
# Build up the regular expression used to recognize the various component of the
# window title.
def labelRegex(label, regex):
    return "(?P<%s>%s)" % (label, regex)
HOST_REGEX = r'(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9]+'
EMAIL_REGEX = r'[a-zA-Z0-9\-]+@' + HOST_REGEX
REGEX_COMPONENTS = {
    # If you add new components, you must also add code that handles the
    # component in accounts.py.
    'title': labelRegex('title', r'.*'),
    'host': labelRegex('host', HOST_REGEX),
    'protocol': labelRegex('protocol', r'\w+'),
    'browser': labelRegex('browser', r'\w+'),
    'username': labelRegex('username', r'\w+'),
    'email': labelRegex('email', EMAIL_REGEX)}
# Hostname in Titlebar browser title regex
HNITB_BROWSER_TITLE_PATTERN = re.compile(
    r'{title} - {host} \({protocol}\)(?: - {browser})?'.format(**REGEX_COMPONENTS))
# Simple browser title regex
SIMPLE_BROWSER_TITLE_PATTERN = re.compile(
    r'{title}(?: - {browser})?'.format(**REGEX_COMPONENTS))
# Recognize components of the url
URL_PATTERN = re.compile(
    r'(?:{protocol}://)?{host}(?:/.*)?'.format(**REGEX_COMPONENTS))
TITLE_PATTERNS = [
    ('hostname-in-titlebar-browser', HNITB_BROWSER_TITLE_PATTERN),
    # You can comment out the entry above if you are not using 'Hostname in
    # Titlebar' extension to Firefox and Thunderbird
    ('simple browser title', SIMPLE_BROWSER_TITLE_PATTERN)]

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
    
    # vim: filetype=python
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
    #     'alphabet': exclude(PRINTABLE, '\\t')
    # or:
    #     'alphabet': ALPHANUMERIC + PUNCTUATION + ' '

    from textwrap import dedent
    from password.charsets import (
        exclude, LOWERCASE, UPPERCASE, LETTERS, DIGITS, ALPHANUMERIC,
        HEXDIGITS, PUNCTUATION, WHITESPACE, PRINTABLE, DISTINGUISHABLE
    )

    # The desired location of the log file (use an absolute path)
    # Adding a suffix of .gpg or .asc causes the file to be encrypted (otherwise
    # it can leak account names).
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
            'alphabet': ALPHANUMERIC + PUNCTUATION,
            'autotype': "{username}{tab}{password}{return}",
        },
        "=num": {  # typically used for PINs
            'password-type': 'chars',
            'num-chars': 4,
            'alphabet': DIGITS,
            'autotype': "{password}{return}",
        },
        "=anum": {  # typically used for web passwords (contains only easily distinguished alphanumeric characters)
            'password-type': 'chars',
            'num-chars': 12,
            'alphabet': DISTINGUISHABLE,
            'autotype': "{username}{tab}{password}{return}",
        },
        "=master": {  # typically used to generate master passwords for pw
            'password-type': 'words',
            'num-words': 8,
        },
        "=extreme": {  # used in situations where there are no limits
            'password-type': 'chars',
            'num-chars': 64,
            'alphabet': exclude(PRINTABLE, '\\t'),
        },

        # Accounts
        # AAAAA
        # BBBBB
        # CCCCC
        # DDDDD
        # EEEEE
        # FFFFF
        # GGGGG
        # HHHHH
        # IIIII
        # JJJJJ
        # KKKKK
        # LLLLL
        # MMMMM
        # NNNNN
        # OOOOO
        # PPPPP
        # QQQQQ
        # RRRRR
        # SSSSS
        # TTTTT
        # UUUUU
        # VVVVV
        # WWWWW
        # XXXXX
        # YYYYY
        # ZZZZZ
        #
        # Place your accounts above. Sort them and place them below the
        # appropriate tab to make them easier to find. Here is a template that
        # shows what an account might contain. Feel free to delete this example
        # along with this comment.
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
        #       'alphabet': DISTINGUISHABLE
        #                           # character set used in passwords
        #                           # construct from character sets
        #       'prefix': '',       # added to the front of passwords
        #       'suffix': '',       # added to the end of passwords
        #   },
    }
    additional_accounts = []

    # vim: filetype=python
''')

# Fields {{{1
# Do not change these (not user configurable)
SEARCH_FIELDS = ['username', 'account', 'email', 'url', 'remarks']
STRING_FIELDS = [
    'alphabet', 'autotype', 'email', 'master', 'prefix',
    'remarks', 'separator', 'suffix', 'template', 'type',
    'username', 'version'
]
INTEGER_FIELDS = ['num-chars', 'num-words']
LIST_FIELDS = ['security questions', 'aliases']
LIST_OR_STRING_FIELDS = ['account', 'window', 'url']
ENUM_FIELDS = {
    'password-type': ['words', 'chars']
}
ALL_FIELDS = (
    STRING_FIELDS + INTEGER_FIELDS + LIST_FIELDS + LIST_OR_STRING_FIELDS +
    [each for each in ENUM_FIELDS.keys()]
)


# vim: set sw=4 sts=4 et:
