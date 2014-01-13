from setuptools import setup
from abraxas.version import VERSION

# Create/update manpage before installing
import manpage
manpage.write()

setup(
    name='abraxas',
    description="password generator",
    author="Kale & Ken Kundert",
    author_email='abraxas@nurdletech.com',
    version=VERSION,
    download_url='git@github.com:KenKundert/abraxas.git',
    scripts=['abraxas.py'],
    packages=['abraxas'],
    py_modules=['fileutils'],
    data_files=[
        ('', ['words']),
        ('man/man1', ['abraxas.1']),
        ('man/man3', ['abraxas.3']),
        ('man/man5', ['abraxas.5']),
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
