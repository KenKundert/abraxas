# Generate a Secret

import hashlib
import string

# Globals {{{1
DEFAULT_PASSPHRASE_LENGTH = 4
DEFAULT_PASSWORD_LENGTH = 12
DEFAULT_SEPARATOR = ' '
DEFAULT_ALPHABET = string.ascii_letters + string.digits

# Utilities {{{1
# Partition a string into chunks, each of chars_per_chunk characters, and return
# them one at a time until either the string is exhausted or num_chars have been
# returned.  In this case, the string consists of hexadecimal characters (0-9,
# a-f), and so each chunk can be treated as a hexadecimal number or
# chars_per_chunk digits.
def _partition(hexstr, chars_per_chunk, num_chunks):
    max_chars = len(hexstr)
    for index in range(num_chunks):
        start = index*chars_per_chunk
        end = (index + 1)*chars_per_chunk
        if end > max_chars:
            break
        yield hexstr[start:end]

# Pass phrase class {{{1
# Reads a dictionary and generates a pass phrase using those words.
# The dictionary is contained in a file either in the settings directory
# or the install directory.
class Passphrase():
    def __init__(self, report):
        self.report = report

    # Check to see if we can access all the words in the dictionary. {{{2
    def check_length(self, words, bits):
        num_words = len(words)
        max_words = 2**bits
        if num_words > max_words:
            self.report(' '.join([
                "There are more words in the dictionary (%s)" % (num_words),
                "than can be used (%s). The rest are ignored." % (max_words)]))

    # Generate a passphrase {{{2
    def generate(self, master_password, account, dictionary, salt=''):
        key = salt
        key += account.get_version()
        key += account.get_id()
        key += master_password
        digest = hashlib.sha512((key).encode('utf-8')).hexdigest()
        length = account.get_num_words(DEFAULT_PASSPHRASE_LENGTH)
        separator = account.get_separator(DEFAULT_SEPARATOR)
        words = dictionary.get_words()

        # Generate pass phrase
        phrase = []
        self.check_length(words, 16)
        for chunk in _partition(digest, 4, length):
            # chunk is a string that contains 4 hexadecimal digits (the
            # characters '0'-'9' and 'a'-'f').  It is converted into an integer
            # between 0 and 65535 that is then used as an index to choose a
            # word from the dictionary.
            index = int(chunk, 16) % len(words)
            phrase += [words[index]]
        passphrase = separator.join(phrase)
        return account.get_prefix() + passphrase + account.get_suffix()

# Password class {{{1
# Generates a password from an alphabet.
class Password():
    def __init__(self, report):
        self.report = report

    # Check to see if we can access all the characters in our alphabet. {{{2
    def check_length(self, alphabet, bits):
        num_chars = len(alphabet)
        max_chars = 2**bits
        if num_chars > max_chars:
            self.report(' '.join([
                "There are more characters in the alphabet" % (self.path),
                "(%s) than can be used (%s)." % (num_chars, max_chars),
                "The rest are ignored."]))

    # Generate a password {{{2
    def generate(self, master_password, account, salt=''):
        key = salt
        key += account.get_version()
        key += account.get_id()
        key += master_password
        digest = hashlib.sha512((key).encode('utf-8')).hexdigest()
        length = account.get_num_chars(DEFAULT_PASSWORD_LENGTH)

        # Generate password
        password = ''
        alphabet = account.get_alphabet(DEFAULT_ALPHABET)
        self.check_length(alphabet, 8)
        for chunk in _partition(digest, 2, length):
            # chunk is a string that contains 2 hexadecimal digits (the
            # characters '0'-'9' and 'a'-'f').  It is converted into an integer
            # between 0 and 255 that is then used as an index to choose a
            # word from the alphabet.
            index = int(chunk, 16) % len(alphabet)
            password += alphabet[index]
        return (account.get_prefix() + password + account.get_suffix())
