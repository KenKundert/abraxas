from setuptools import setup
from manpage import version

# Create/update manpage before installling
import manpage
manpage.write()

setup(
    name='pw'
  , description="password generator"
  , author="Kale Kundert & Ken Kundert"
  , author_email='kaleAndKen@theKunderts.net'
  , version=version
  , download_url='git@github.com:KenKundert/password.git'
  , scripts=['pw']
  , packages=['password']
  , py_modules=['cmdline', 'fileutils']
  , data_files=[
        ('', ['words']),
        ('man/man1', ['pw.1']),
        ('man/man3', ['pw.3']),
        ('man/man5', ['pw.5']),
    ]
  , license='GPLv3'
)
