from setuptools import setup

# Create/update manpage before installling
import manpage
manpage.write()

setup(
    name='pw'
  , description="password generator"
  , author="Kale Kundert & Ken Kundert"
  , author_email='kaleAndKen@theKunderts.net'
#  , download_url='git://hacking.kxgames.net/pw'
  , scripts=['pw']
  , py_modules=['pw', 'cursor', 'secrets', 'dialog']
  , data_files=[
        ('', ['words']),
        ('man/man1', ['pw.1']),
        ('man/man3', ['pw.3']),
        ('man/man5', ['pw.5']),
    ]
)