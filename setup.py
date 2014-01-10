from setuptools import setup
from password.version import VERSION

# Create/update manpage before installing
import manpage
manpage.write()

setup(
    name='pw',
    description="password generator",
    author="Kale Kundert & Ken Kundert",
    author_email='kaleAndKen@theKunderts.net',
    version=VERSION,
    download_url='git@github.com:KenKundert/password.git',
    scripts=['pw'],
    packages=['password'],
    py_modules=['fileutils'],
    data_files=[
        ('', ['words']),
        ('man/man1', ['pw.1']),
        ('man/man3', ['pw.3']),
        ('man/man5', ['pw.5']),
    ],
    license='GPLv3',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Topic :: Utilities",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
    ]
)


# vim: set sw=4 sts=4 et:
