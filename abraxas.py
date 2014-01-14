#!/usr/bin/env python

# Abraxas Password Generator
# Copyright (C) 2013-14 Kenneth S. Kundert and Kale B. Kundert
#
# Generates passwords and pass phrases based on stored account information.

# Imports {{{1
from abraxas.generate import PasswordGenerator, PasswordError
from abraxas.writer import PasswordWriter
from abraxas.prefs import (
    SEARCH_FIELDS, DEFAULT_SETTINGS_DIR, DEFAULT_ARCHIVE_FILENAME,
    BROWSERS, DEFAULT_BROWSER
)
from abraxas.logger import Logging
from fileutils import (
    getTail as get_tail,
    makePath as make_path,
    execute, ExecuteError
)
import argparse
import sys

# CommandLine class {{{1
class CommandLine:
    def __init__(self, argv):
        self.prog_name = get_tail(argv[0])
        parser = argparse.ArgumentParser(
            add_help=False, description="Generate strong and unique password.")
        arguments = parser.add_argument_group('arguments')
        arguments.add_argument(
            'account', nargs='?', default='',
            help="Generate password specific to this account.")
        parser.add_argument(
            '-q', '--question', type=int, metavar='<N>',
            default=None, help="Output security question N.")
        parser.add_argument(
            '-P', '--password', action='store_true',
            help="Output the password (default if nothing else is requested).")
        parser.add_argument(
            '-N', '--username', action='store_true',
            help="Output the username.")
        parser.add_argument(
            '-A', '--account-number', action='store_true',
            help="Output the account number.")
        parser.add_argument(
            '-E', '--email', action='store_true', help="Output the email.")
        parser.add_argument(
            '-U', '--url', action='store_true', help="Output the URL.")
        parser.add_argument(
            '-R', '--remarks', action='store_true',
            help="Output remarks.")
        parser.add_argument(
            '-i', '--info', action='store_true',
            help="Output everything, except the password.")
        parser.add_argument(
            '-a', '--all', action='store_true',
            help="Output everything, including the password.")
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            '-c', '--clipboard', action='store_true',
            help="Write output to clipboard rather than stdout.")
        group.add_argument(
            '-t', '--autotype', action='store_true',
            help=(' '.join([
                "Mimic keyboard to send output to the active window rather",
                "than stdout. In this case any command line arguments that",
                "specify what to output are ignored and the autotype entry",
                "scripts the output."])))
        parser.add_argument(
            '-f', '--find', type=str, metavar='<str>',
            help=(' '.join([
                "List any account that contains the given string",
                "in its ID or aliases."])))
        parser.add_argument(
            '-s', '--search', type=str, metavar='<str>',
            help=(' '.join([
                "List any account that contains the given string in",
                "%s, or its ID." % ', '.join(SEARCH_FIELDS)])))
        parser.add_argument(
            '-S', '--stateless', action='store_true',
            help="Do not use master password or accounts file.")
        parser.add_argument(
            '-T', '--template',
            type=str, metavar='<template>', default=None,
            help="Template to use if account is not found.")
        parser.add_argument(
            '-b', '--default-browser', action='store_true',
            help="Open account in the default browser.")
        parser.add_argument(
            '-B', '--browser', type=str, metavar='<browser>',
            help="Open account in the specified browser (choose from %s)." %
                ', '.join(BROWSERS))
        parser.add_argument(
            '-l', '--list', action='store_true',
            help=(' '.join([
                "List available master passwords and templates (only pure",
                "templates are listed, not accounts, even though accounts",
                "can be used as templates)."])))
        parser.add_argument(
            '-w', '--wait', type=float, default=60, metavar='<secs>',
            help=(' '.join([
                "Wait this long before clearing the secret",
                "(use 0 to disable)."])))
        parser.add_argument(
            '--archive', action='store_true',
            help=("Archive all the secrets to %s." % make_path(
                DEFAULT_SETTINGS_DIR, DEFAULT_ARCHIVE_FILENAME)))
        parser.add_argument(
            '--changed', action='store_true',
            help=(
                "Identify all secrets that have changed since last archived."))
        parser.add_argument(
            '-I', '--init', type=str, metavar='<GPG ID>',
            help=(' '.join([
                "Initialize the master password and account files in",
                DEFAULT_SETTINGS_DIR,
                "(but only if they do not already exist)."])))
        parser.add_argument(
            '-h', '--help',  action='store_true',
            help="Show this help message and exit.")

        args = parser.parse_args()

        # If requested, print help message and exit
        if args.help:
            parser.print_help()
            sys.exit()

        # Save all the command line arguments as attributes of self
        self.__dict__.update(args.__dict__)

    def name_as_invoked(self):
        return self.prog_name


# Main {{{1
if __name__ == "__main__":
    cmd_line = CommandLine(sys.argv)
    try:
        with Logging(argv=sys.argv, exception=PasswordError) as logging:
            generator = PasswordGenerator(
                logger=logging,
                init=cmd_line.init,
                stateless=cmd_line.stateless)
            if cmd_line.init:
                logging.terminate()

            # Open the accounts file
            generator.read_accounts(cmd_line.template)

            # If requested, list the available templates and then exit
            if cmd_line.list:
                logging.display(
                    "MASTER PASSWORDS:\n   " + '\n   '.join(
                        sorted(generator.master_password.password_names())))
                logging.display(
                    "\nTEMPLATES:\n   " + '\n   '.join(
                        sorted(generator.all_templates())))
                logging.terminate()

            # If requested, search the account database and exit after printing
            # results
            def print_search_results(search_term, search_func):
                to_print = []
                for acct, aliases in search_func(search_term):
                    aliases = ' (%s)' % (', '.join(aliases)) if aliases else ''
                    to_print += [acct + aliases]
                logging.display(search_term + ':')
                logging.display('    ' + ('\n    '.join(sorted(to_print))))

            if cmd_line.find:
                print_search_results(cmd_line.find, generator.find_accounts)
                logging.terminate()

            if cmd_line.search:
                print_search_results(
                    cmd_line.search, generator.search_accounts)
                logging.terminate()

            if cmd_line.changed:
                generator.print_changed_secrets()
                logging.terminate()
            if cmd_line.archive:
                generator.archive_secrets()
                logging.terminate()

            # Select the requested account
            account = generator.get_account(cmd_line.account)

            # If requested, open accounts webpage in browser and then exit.
            if cmd_line.browser or cmd_line.default_browser:
                try:
                    if cmd_line.default_browser:
                        cmd = BROWSERS[DEFAULT_BROWSER]
                    else:
                        try:
                            cmd = BROWSERS[cmd_line.browser]
                        except KeyError:
                            logging.error(
                                'Unknown browser: %s, choose from %s.' % (
                                    cmd_line.browser,
                                    ', '.join(BROWSERS)))
                    urls = account.get_field('url', [])
                    if type(urls) == str:
                        urls = [urls]
                    if urls:
                        url = urls[0]
                            # choose first url if there are more than one
                        logging.log("running '%s'" % (cmd % url))
                        execute(cmd % url)
                        logging.terminate()
                    else:
                        logging.error('url is unknown')
                except ExecuteError as err:
                    logging.error(str(err))

            # Create the secrets writer
            style = 'c' if cmd_line.clipboard else (
                't' if cmd_line.autotype else 's')
            writer = PasswordWriter(style, generator, cmd_line.wait, logging)

            # Process the users output requests
            if cmd_line.autotype:
                writer.write_autotype()
            else:
                if cmd_line.username or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('username')
                if cmd_line.account_number or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('account')
                if cmd_line.email or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('email')
                if cmd_line.url or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('url')
                if cmd_line.remarks or cmd_line.info or cmd_line.all:
                    writer.write_account_entry('remarks')
                if cmd_line.info or cmd_line.all:
                    writer.write_question()
                    writer.write_unknown_entries()
                if cmd_line.question is not None:
                    writer.write_answer(cmd_line.question)
                if cmd_line.password or cmd_line.all or writer.is_empty():
                    writer.write_password()

            # Output everything that the user requested.
            writer.process_output()
            logging.terminate()
    except PasswordError as err:
        sys.exit('%s: %s' % (cmd_line.name_as_invoked(), str(err)))
    except KeyboardInterrupt:
        sys.exit('Killed by user')

# vim: set filetype=python sw=4 sts=4 et ai:
