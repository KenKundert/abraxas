# Abraxas Logging
#
# Log output to a file.
#
# Copyright (C) 2013-14 Kenneth S. Kundert and Kale Kundert

# License (fold)
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

# Imports (fold)
from __future__ import print_function, division
from fileutils import expandPath as expand_path, getExt as get_extension
from fileutils import Execute, ExecuteError
from abraxas.prefs import DEBUG, NOTIFIER_NORMAL, NOTIFIER_ERROR
import sys
import os


class Logging:
    """
    Abraxas Logger

    Handles all messaging for Abraxas. Copies all messages to the logfile while
    sending most to standard out as well.
    """

    def __init__(
        self, logfile=None, argv=None, prog_name=None, use_notifier=False,
        output_callback=None, exception=None
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
        use_notifier (bool)
            Send messages to notifier rather than stdout.
        output_callback (function)
            This function will be called with any normal output. It takes a
            single argument, a string, that contains the message. If not
            provided, output will be sent to standard output.
        exception (exception object)
            This exception will be raised rather than exiting if provided when
            an error occurs. If not provided, program will exit. The exception
            should take one argument, the error message.

        Messages are cached until the logger terminates (this is because the 
        logfile may not be known before the first messages need to be logged).  
        The messages are only written to the logfile upon termination of the 
        logger.  As such, the logger must be terminated properly for the 
        logfile to be created. To assure this happens, you to create the logger 
        using a with statement.  Example:

            with Logging(argv=sys.argv) as logger:
                ...
        """
        self.logfile = logfile
        self.use_notifier = use_notifier
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
        self.log("Set DEBUG=True in abraxas/prefs.py to enable a detailed log.")
        self.debug("Debug logging is on (should be off in normal operation).")
        self.prog_name = prog_name
        if argv and not prog_name:
            self.prog_name = argv[0]

    def set_logfile(self, logfile, gpg, gpg_id):
        """
        Set the logfile name and GPG parameters.

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

    def display(self, msg):
        """Display the message on standard out and log it."""
        self.log(msg)
        if self.output_callback:
            self.output_callback(msg)
        elif self.use_notifier and NOTIFIER_NORMAL:
            try:
                Execute(NOTIFIER_NORMAL + [msg])
            except ExecuteError as err:
                self.error('Failed to run notifier: %s' % str(err))
        else:
            print(msg)

    def log(self, msg):
        """Log the message."""
        if msg:
            self.cache.append(msg)

    def debug(self, msg):
        """Log the message if DEBUG is set."""
        if DEBUG and msg:
            self.cache.append(msg)

    def error(self, msg):
        """Log and display the message, then exit.

        Once this method is called, execution never returns to the calling
        program.
        """
        self.log(msg)
        if self.exception:
            raise self.exception(msg)
        else:
            msg = [self.prog_name, msg] if self.prog_name else [msg]
            if self.use_notifier and NOTIFIER_ERROR:
                try:
                    Execute(NOTIFIER_ERROR + msg)
                except ExecuteError as err:
                    sys.exit('Failed to run notifier: %s' % str(err))
            sys.exit(': '.join(msg))

    def terminate(self):
        """Normal termination.

        Call this to terminate your program normally. Once this method is
        called, execution never returns to the calling program.
        """
        self.log('Terminates normally.')
        sys.exit()

    def _terminate(self):
        if not self.logfile:
            return
        contents = '\n'.join(self.cache) + '\n'
        filename = expand_path(self.logfile)

        if get_extension(filename) in ['gpg', 'asc']:
            encrypted = self.gpg.encrypt(
                contents.encode('utf8', 'ignore'),
                self.gpg_id, always_trust=True, armor=True
            )
            if not encrypted.ok:
                sys.stderr.write(
                    "%s: unable to encrypt.\n%s" % (filename, encrypted.stderr)
                )
            contents = str(encrypted)
        try:
            with open(filename, 'w') as file:
                file.write(contents)
            os.chmod(filename, 0o600)
        except IOError as err:
            sys.stderr.write('%s: %s.\n' % (err.filename, err.strerror))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self._terminate()
