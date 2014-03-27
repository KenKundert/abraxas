# Abraxas Password Writer
#
# Given a secret (password or passphrase) the password writer is responsible 
# for getting it to the user in reasonably secure manners.
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
import abraxas.cursor as cursor
from abraxas.prefs import (
    LABEL_COLOR, LABEL_STYLE, XDOTOOL, XSEL, ALL_FIELDS, INITIAL_AUTOTYPE_DELAY
)
from fileutils import Execute, ExecuteError
from time import sleep
import re


def indent(text, prefix='    '):
    # Indent a string
    # This should be provided by textwrap, but is not available from older 
    # versions of python.
    return '\n'.join(
        [prefix + line if line else line for line in text.split('\n')])


class PasswordWriter:
    """
    Abraxas Password Writer

    Used to get account information to the user.
    """

    # PasswordWriter is responsible for sending output to the user. It has four 
    # backends, one that writes verbosely to standard output, one that writes 
    # quietly to standard output, one that writes to the clipboard, and one that 
    # autotypes (mimics the keyboard).  To accommodate the three backends the 
    # output is gathered up and converted into a script.  That script is 
    # interpreted by the appropriate backend to produce the output.  The script 
    # is a sequence of commands each with an argument.  Internally the script is 
    # saved as a list of tuples. The first value in the tuple is the name of the 
    # command.  Several commands are supported.
    #    write_verbatim() --> ('verb', <str>)
    #        Outputs the argument verbatim.
    #    write_account_entry() --> ('interp', <label>)
    #        Interpolates information from the account file into the output.
    #        The argument is the item to be interpolated (username, url, etc.)
    #    write_unknown_entries() --> ('unknown')
    #        Interpolates any unrecognized fields in the account into the
    #        output.
    #    write_password() --> ('password')
    #        Outputs the password as a secret (the writer does its best to keep
    #        it secure).
    #    write_question() --> ('question', [<int>])
    #        Outputs security question <int>, or all the available security
    #        questions if <int> is not given. The answer is not included in the
    #        response.
    #    write_answer() --> ('answer', <int>)
    #        Outputs the answer to a security question as a secret (the output
    #        does its best to keep it secure).  The argument is the index
    #        of the question.
    #    sleep() --> ('sleep', <real>)
    #        Waits before continuing. The argument is the number of seconds to
    #        wait.

    def __init__(self, output, generator, wait=60, logger=None):
        """
        Arguments:
        output (string)
            Specify either 'clipboard', 'autotype', 'quiet', or 'standard'.
        generator (abraxas generator object)
            The password generator.
        wait (int)
            The number of seconds to wait after offering the user the password.
        logger (logger object)
            Instance of class that provides display(), log(), and error()
            methods:
                display(msg): called when a message is to be sent to the user.
                log(msg) is called when a message is only to be logged.
                error(msg): called when an error has occurred,
                            should not return.
        """
        self.output = output
        self.wait = wait
        self.generator = generator
        self.logger = logger if logger else generator.logger
        self.script = []

    def is_empty(self):
        return not self.script

    def write_verbatim(self, text):
        """
        Specify a string to output to user when output is processed.
        """
        self.script += [('verb', text)]

    def write_account_entry(self, label):
        """
        Specify an account field to output to user when output is processed.
        """
        self.script += [('interp', label)]

    def write_unknown_entries(self):
        """
        Specify that all unrecognized account fields should be output when
        output is processed.
        """
        self.script += [('unknown',)]

    def write_password(self):
        """
        Specify that the password should be output when output is processed.
        """
        self.script += [('password',)]

    def write_question(self, num=None):
        """
        Specify that a security question should be output when output is
        processed.
        """
        self.script += [('question', num)]

    def write_answer(self, num):
        """
        Specify that the answer to a security question should be output when
        output is processed.
        """
        self.script += [('answer', num)]

    def sleep(self, delay):
        """
        Specify that <delay> seconds should pass before the next thing is sent
        to the output.
        """
        self.script += [('sleep', delay)]

    def write_autotype(self):
        """
        Process the account autotype script send what ever it specifies to the
        output when the output is processed.
        """
        regex = re.compile(r'({\w+})')
        for term in regex.split(self.generator.account.get_autotype()):
            if term and term[0] == '{' and term[-1] == '}':
                cmd = term[1:-1].lower()
                if cmd in ['username', 'account', 'url', 'email', 'remarks']:
                    self.write_account_entry(cmd)
                elif cmd == 'password':
                    self.write_password()
                elif cmd == 'tab':
                    self.write_verbatim('\t')
                elif cmd == 'return':
                    self.write_verbatim('\n')
                elif cmd.startswith('sleep'):
                    cmd = cmd.split()
                    try:
                        assert cmd[0] == 'sleep'
                        assert len(cmd) == 2
                        self.sleep(float(cmd[1]))
                    except (AssertionError, TypeError):
                        self.logger.display("ERROR in autotype: %s" % term)
                        return
                elif cmd.startswith('question'):
                    cmd = cmd.split()
                    try:
                        assert cmd[0] == 'question'
                        assert len(cmd) == 2
                        self.write_question(int(cmd[1]))
                    except (AssertionError, TypeError, IndexError):
                        self.logger.display("ERROR in autotype: %s" % term)
                        return
                elif cmd.startswith('answer'):
                    cmd = cmd.split()
                    try:
                        assert cmd[0] == 'answer'
                        assert len(cmd) == 2
                        self.write_answer(int(cmd[1]))
                    except (AssertionError, TypeError, IndexError):
                        self.logger.display("ERROR in autotype: %s" % term)
                        return
                else:
                    self.logger.display("ERROR in autotype: %s" % term)
                    return
            else:
                if (term):
                    self.write_verbatim(term)

    def process_output(self):
        """
        Process the output.

        Everything that was stashed away by the various write_ methods should
        now be sent to the user using the requested method.
        """
        if self.output == 'autotype':
            self._process_output_to_autotype()
        elif self.output == 'clipboard':
            self._process_output_to_clipboard()
        elif self.output == 'quiet':
            self._process_output_to_quiet()
        elif self.output == 'standard':
            self._process_output_to_stdout()
        else:
            raise NotImplementedError


    def _process_output_to_stdout(self):
        label_password = len(self.script) > 1

        def highlight(label, value):
            # Attach color label to a value
            return (cursor.color(
                label.upper() + ':', LABEL_COLOR, LABEL_STYLE) + ' ' + value)

        def display_secret(label, secret):
            # Send output to stdout with the labels.
            if self.wait:
                text = highlight(label, secret)
                try:
                    cursor.write(text)
                    sleep(self.wait)
                    cursor.clear()
                except KeyboardInterrupt:
                    cursor.clear()
            elif label_password:
                print(highlight(label, secret))
            else:
                print(secret)

        def display_field(label, value):
            # Send field to stdout with the labels.
            if value:
                if type(value) == list:
                    print(highlight(label, '\n    '+',\n    '.join(value)))
                elif '\n' in value:
                    print(highlight(label, '\n'+indent(value.strip(), '    ')))
                else:
                    print(highlight(label, value.rstrip()))

        # Execute the script
        for action in self.script:
            if action[0] == 'interp':
                display_field(
                    action[1],
                    self.generator.account.get_field(action[1]))
            elif action[0] == 'unknown':
                fields = sorted(
                    set(self.generator.account.get_data().keys()) -
                    set(ALL_FIELDS))
                for field in fields:
                    display_field(
                        field, self.generator.account.get_field(field))
            elif action[0] == 'password':
                display_secret(
                    'PASSWORD',
                    self.generator.generate_password()
                )
            elif action[0] == 'question':
                questions = self.generator.account.get_field(
                    'security questions')
                if questions:
                    if action[1] is None:
                        for index, question in enumerate(questions):
                            print(highlight('QUESTION %d' % index, question))
                    else:
                        try:
                            print(highlight(
                                'QUESTION %d' % action[1],
                                questions[action[1]]))
                        except IndexError:
                            print(highlight(
                                'QUESTION %d' % action[1],
                                '<not available>'))
            elif action[0] == 'answer':
                question, answer = self.generator.generate_answer(action[1])
                if answer:
                    display_secret(question, answer)
            else:
                raise NotImplementedError
        self.logger.log('Writing to stdout.')

    def _process_output_to_clipboard(self):
        # Send output to clipboard without the labels.
        lines = []

        # Execute the script
        for action in self.script:
            if action[0] == 'interp':
                value = self.generator.account.get_field(action[1])
                if type(value) == list:
                    lines += ["%s: %s" % (action[1], ', '.join(value))]
                elif value:
                    lines += ["%s: %s" % (action[1], value.rstrip())]
            elif action[0] == 'unknown':
                fields = sorted(
                    set(self.generator.account.get_data().keys()) -
                    set(ALL_FIELDS))
                for field in fields:
                    value = self.generator.account.get_field(field)
                    if type(value) == list:
                        lines += ["%s: %s" % (field, ', '.join(value))]
                    elif value:
                        lines += ["%s: %s" % (field, value.rstrip())]
            elif action[0] == 'password':
                lines += [self.generator.generate_password()]
            elif action[0] == 'question':
                questions = self.generator.account.get_field(
                    'security questions')
                if questions:
                    if action[1] is None:
                        for index, question in enumerate(questions):
                            lines += ['question %d: %s' % (index, question)]
                    else:
                        try:
                            lines += ['question %d: %s' % (
                                action[1], questions[action[1]])]
                        except IndexError:
                            lines += [
                                'question %d: <not available>' % action[1]]
            elif action[0] == 'answer':
                question, answer = self.generator.generate_answer(action[1])
                if answer:
                    lines += [answer]
            else:
                raise NotImplementedError
        text = '\n'.join(lines)
        self.logger.log('Writing to clipboard.')

        # Use 'xsel' to put the information on the clipboard.
        # This represents a vulnerability, if someone were to replace xsel they
        # could steel my passwords. This is why I use an absolute path. I tried
        # to access the clipboard directly using GTK but I cannot get the code
        # to work.
        try:
            Execute([XSEL, '-b', '-i'], stdin=text)
        except ExecuteError as err:
            self.logger.error(str(err))
        try:
            sleep(self.wait)
        except KeyboardInterrupt:
            pass
        try:
            Execute([XSEL, '-b', '-c'])
        except ExecuteError as err:
            self.logger.error(str(err))

        # Use Gobject Introspection (GTK) to put the information on the
        # clipboard (for some reason I cannot get this to work).
        #try:
        #    from gi.repository import Gtk, Gdk
        #
        #    clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        #    clipboard.set_text(text, len(text))
        #    clipboard.store()
        #    sleep(self.wait)
        #    clipboard.clear()
        #except ImportError:
        #    error('Clipboard is not supported.')

    def _process_output_to_autotype(self):
        # Mimic a keyboard to send output to the active window.

        def autotype(text):
            # Use 'xdotool' to mimic the keyboard.
            # For reasons I do not understand, sending a newline to xdotool
            # does not always result in a newline coming out. So separate out
            # the newlines and send them using as an explicit 'key' stroke.
            regex = re.compile(r'(\n)')
            segments = regex.split(text)
            try:
                for segment in segments:
                    if segment == '\n':
                        Execute([XDOTOOL, 'key', 'Return'])
                    elif segment != '':
                        # send text to xdotool through stdin so it cannot be
                        # seen with ps
                        Execute(
                            [XDOTOOL, '-'],
                            stdin='getactivewindow type "%s"' % segment
                        )
            except ExecuteError as err:
                self.logger.error(str(err))

        # Execute the script
        text = []
        scrubbed = []
        sleep(INITIAL_AUTOTYPE_DELAY)
        for action in self.script:
            if action[0] == 'verb':
                text += [action[1]]
                scrubbed += [action[1]]
            elif action[0] == 'sleep':
                autotype(''.join(text))
                text = []
                sleep(action[1])
                scrubbed += ['<sleep %s>' % action[1]]
            elif action[0] == 'interp':
                value = self.generator.account.get_field(action[1])
                if type(value) == list:
                    value = ', '.join(value)
                elif value:
                    value = value.rstrip()
                else:
                    value = '<%s unknown>' % action[1]
                text += [value]
                scrubbed += [value]
            elif action[0] == 'password':
                text += [self.generator.generate_password()]
                scrubbed += ['<<password>>']
            elif action[0] == 'question':
                questions = self.generator.account.get_field(
                    'security questions')
                if questions:
                    if action[1] is None:
                        for index, question in enumerate(questions):
                            value = 'question %d: %s' % (index, question)
                    else:
                        try:
                            value = 'question %d: %s' % (
                                action[1], questions[action[1]])
                        except IndexError:
                            value = 'question %d: <not available>' % action[1]
                    text += [value]
                scrubbed += [value]
            elif action[0] == 'answer':
                question, answer = self.generator.generate_answer(action[1])
                if answer:
                    text += [answer]
                    scrubbed += ["<<answer to '%s'>>" % question]
            else:
                raise NotImplementedError
        self.logger.log('Autotyping "%s".' % ''.join(scrubbed))
        autotype(''.join(text))

    def _process_output_to_quiet(self):
        # Write only essential information to stdout.  This is meant to 
        # facilitate scripting with abraxas.

        for action in self.script:
            if action[0] == 'interp':
                action = self.generator.account.get_field(action[1])
                if action:
                    print(action)

            elif action[0] == 'password':
                print(self.generator.generate_password())

            elif action[0] == 'answer':
                print(self.generator.generate_answer(action[1])[1])

            else:
                pass

        self.logger.log(
                'Writing quietly to stdout.  Some output may be ignored.')

# vim: set sw=4 sts=4 et:
