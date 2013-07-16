"""Character Sets

Defines strings of characters and an exclude function that can be used either as
the alphabets for you character-base passwords or as building blocks used to
construct a new alphabet for you passwords.

Example:
To create an alphabet with all characters except tabs use either:
    'alphabet': exclude(printable, '\t')
or:
    'alphabet': alphanumeric + punctuation + ' '
"""

# Exclude function
def exclude(chars, exclusions):
    """Exclude Characters

    Use this to strip characters from a character set.
    """
    return chars.translate(str.maketrans('', '', exclusions))

# Character sets
# Use these to construct alphabets by summing together the ones you want.
lowercase = "abcdefghijklmnopqrstuvwxyz"
uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
letters = lowercase + uppercase
digits = "0123456789"
alphanumeric = letters + digits
hexdigits = "0123456789abcdef"
punctuation = """!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
whitespace = " \t"
printable = alphanumeric + punctuation + whitespace
distinguishable = exclude(alphanumeric, 'Il1O0\\t')
