# Password Generator
#
# Preferences.
#
# Copyright (C) 2013 Kenneth S. Kundert and Kale B. Kundert

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
STRING_FIELDS = [
    'alphabet', 'autotype', 'email', 'master', 'prefix',
    'remarks', 'separator', 'suffix', 'template', 'type', 'url',
    'username', 'version'
]
INTEGER_FIELDS = ['num-chars', 'num-words']
LIST_FIELDS = ['security questions', 'aliases']
LIST_OR_STRING_FIELDS = ['account', 'window']
ENUM_FIELDS = {
    'password-type': ['words', 'chars']
}
ALL_FIELDS = (
    STRING_FIELDS + INTEGER_FIELDS + LIST_FIELDS + LIST_OR_STRING_FIELDS +
    [each for each in ENUM_FIELDS.keys()]
)
# Use absolute paths for xdotool and xsel
# Makes it harder for someone to replace them so as to expose the secrets.
XDOTOOL = '/usr/bin/xdotool'
XSEL = '/usr/bin/xsel'
GPG_BINARY = 'gpg2'
SECRETS_SHA1 = "5d0182e4b939352b352027201008e8af473ee612"
CHARSETS_SHA1 = "6c9644ab97b1f53f982f70e2808f0f1e850e1fe1"
LABEL_COLOR = 'yellow'
    # choose from normal, black, red, green, yellow, blue, magenta, cyan, white
LABEL_STYLE = 'normal'
    # choose from normal, bright, reverse, dim, underline, blink, reverse,
    # invisible (these need to be implemented by underlying terminal, and some
    # are not (such a blink and dim)
INITIAL_AUTOTYPE_DELAY=0.5

# Associate a command with a browser key.
# The command must contain a single %s, which is replaced with URL.
BROWSERS = {
    'f': 'firefox -new-tab %s > /dev/null',
    'v': 'vimprobable2 %s',
}
DEFAULT_BROWSER = 'f'

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
    from password.charsets import (
        exclude, lowercase, uppercase, letters, digits, alphanumeric,
        hexdigits, punctuation, whitespace, printable, distinguishable
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
            'alphabet': alphanumeric + punctuation,
            'autotype': "{username}{tab}{password}{return}",
        },
        "=num": {  # typically used for PINs
            'password-type': 'chars',
            'num-chars': 4,
            'alphabet': digits,
            'autotype': "{password}{return}",
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
        #       'alphabet': distinguishable
        #                           # character set used in passwords
        #                           # construct from character sets
        #       'prefix': '',       # added to the front of passwords
        #       'suffix': '',       # added to the end of passwords
        #   },
    }
    additional_accounts = []
''')


