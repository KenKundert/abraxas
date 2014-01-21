from setuptools import setup
from abraxas.version import VERSION

# Create/update manpage before installing
import manpage
manpage.write()

def get_long_description():
    contents = []
    for each in ['README.rst', 'CHANGES.rst']:
        with open(each) as f:
            contents += [f.read()]
    return '\n\n'.join(contents)

def main():
    setup(
        name='abraxas',
        description="password generator",
        long_description=get_long_description(),
        author="Kale & Ken Kundert",
        author_email='abraxas@nurdletech.com',
        version=VERSION,
        download_url='git@github.com:KenKundert/abraxas.git',
        scripts=['main.py'],
        packages=['abraxas'],
        py_modules=['fileutils'],
        data_files=[
            ('', ['words']),
            ('man/man1', ['abraxas.1']),
            ('man/man3', ['abraxas.3']),
            ('man/man5', ['abraxas.5']),
        ],
        license='GPLv3',
        platforms=['linux'],
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

main()
# vim: set sw=4 sts=4 et:
