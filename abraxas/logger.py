# Abraxas Logging
#
# Log output to a file.
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
from __future__ import print_function, division
from fileutils import expandPath as expand_path, getExt as get_extension
from abraxas.prefs import DEBUG
import sys
import os


# Logging {{{1
# Log messages to a file
class Logging:
    """
    Abraxas Logger

    Handles all messaging for Abraxas. Copies all messages to the logfile while
    sending most to standard out as well.
    """
    def __init__(self,
        logfile=None,
        argv=None,
        prog_name=None,
        output_callback=None,
        exception=None
    ):
        """
        Arguments:
        logfile (string)
            Path to user's logfile (relative to users config directory).
            Use set_logfile() if you do not know logfile when starting up or if
            you need the logfile to be encrypted.
        argv (list of strings)
            System command line arguments (logged).
        prog_name (string)
            Program name, pre-pended to error messages.
        output_callback (function)
            This function will be called with any normal output. It takes a
            single argument, a string, that contains the message. If not
            provided, output will be sent to standard output.
        exception (exception object)
            This exception will be raised rather than exiting if provided when
            an error occurs. If not provided, program will exit. The exception
            should take one argument, the error message.

        You generally want to invoke Logging with a 'with' statement to assure
        that log file gets generated.  Example:

            with Logging(argv=sys.argv) as logger:
                ...
        """
        self.logfile = logfile
        self.output_callback = output_callback
        self.exception = exception
        self.cache = []
        if not argv:
            argv = sys.argv
        if argv:
            try:
                from datetime import datetime
                now = datetime.now().strftime(
                    " on %A, %d %B %Y at %I:%M:%S %p")
            except:
                now = ""
            self.log("Invoked as '%s'%s." % (' '.join(argv), now))
        self.debug("Debug logging is on (should be off in normal operation).")
        self.prog_name = prog_name
        if argv and not prog_name:
            self.prog_name = argv[0]

    # Set the logfile name and gpg parameters.
    def set_logfile(self, logfile, gpg, gpg_id):
        """
        Set the logfile.

        Arguments:
        logfile (string)
            Path to user's logfile (relative to users config directory).
        gpg (gnupg object)
            Instance of gnupg class.
        gpg_id (string)
            The user's GPG ID.
        The last two must be specified if the logfile has an encryption
        extension (.gpg or .asc).
        """
        self.logfile = logfile if logfile else self.logfile
        self.gpg = gpg
        self.gpg_id = gpg_id

    # Print the messages and also send it to the logfile.
    def display(self, msg):
        """Display the message on standard out and log it."""
        self.log(msg)
        if self.output_callback:
            self.output_callback(msg)
        else:
            print(msg)

    # Only send the message to the logfile.
    def log(self, msg):
        """Log the message."""
        if msg:
            self.cache.append(msg)

    # Only send the message to the logfile.
    def debug(self, msg):
        """Log the message if DEBUG is set."""
        if DEBUG and msg:
            self.cache.append(msg)

    # Log a message and then throw an exception.
    def error(self, msg):
        """Log and display the message, then exit.

        Once this method is called, execution never returns to the calling
        program.
        """
        self.log(msg)
        if self.exception:
            raise self.exception(msg)
        else:
            if self.prog_name:
                sys.exit("%s: %s" % (self.prog_name, msg))
            else:
                sys.exit(msg)

    # Exit cleanly.
    def terminate(self):
        """Normal termination.

        Call this to terminate your program normally. Once this method is
        called, execution never returns to the calling program.
        """
        self.log('Terminates normally.')
        sys.exit()

    # Close the logfile.
    def _terminate(self):
        if not self.logfile:
            return
        contents = '\n'.join(self.cache) + '\n'
        filename = expand_path(self.logfile)

        if get_extension(filename) in ['gpg', 'asc']:
            encrypted = self.gpg.encrypt(
                contents, self.gpg_id, always_trust=True, armor=True
            )
            if not encrypted.ok:
                sys.stderr.write(
                    "%s: unable to encrypt.\n%s" % (filename, encrypted.stderr))
            contents = str(encrypted)
        try:
            with open(filename, 'w') as file:
                file.write(contents)
            os.chmod(filename, 0o600)
        except IOError as err:
            sys.stderr.write('%s: %s.\n' % (err.filename, err.strerror))

    # Support for the with statement
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self._terminate()
