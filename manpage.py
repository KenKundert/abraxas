#!/bin/env python3
# Convert the restructured text version of the manpage to a nroff manpage file.

from docutils.core import publish_string
from docutils.writers import manpage
from textwrap import dedent
import re
from pw import search_fields

date = "2013-02-12"
version = "1.0.0"

# Program Manpage {{{1
programManpage = {
    'name': 'pw',
    'sect': '1',
    'contents': r"""{
        ====
         pw
        ====

        ------------------
        password generator
        ------------------

        :Author: Ken Kundert <pw@nurdletech.com>
        :Date: {date}
        :Version: {version}
        :Manual section: 1

        .. :Copyright: public domain
        .. :Manual group: Utilities

        SYNOPSIS
        ========
        **pw** [*options*] [*account*]

        DESCRIPTION
        ===========
        **pw** is a password generator that is capable of generating two types 
        of passwords, character based (passwords) or word based (pass phrases). 
        To see the attractiveness of pass phrases, see http://xkcd.com/936/.

        To use it, one creates a file that contains information about each of 
        his or her accounts.  Amongst that information would be information that 
        controls how the passwords are generated. This file is not encrypted. 
        Another file is created that contains one or more master passwords. This 
        file is gpg encrypted.

        The intent is for these files not include the passwords for your 
        accounts.  Rather, the passwords are recomputed when needed from the 
        account information and from the master password. This makes it easy to 
        share passwords with others without having to pass the passwords back 
        and forth.  It is only necessary to create a shared master password in 
        advance. Then new passwords can be created on the fly by either party.

        This is one way in which the availability of multiple master password is 
        useful in several common situations.  Two or more people can share 
        a master password and then create consistent passwords without having to 
        communicate and store the passwords. Thus, you might have a master 
        password for your personal needs, and then another for each person you 
        collaborate with.
        Second, it allows you to transition to a new master password without 
        having to update all of your existing passwords.  Simply create all new 
        passwords using the new master password.  The existing passwords can be 
        updated on an as-needed basis.

        To generate a password for an account that exists in your accounts file, 
        you would use::

            pw <account>

        where <account> is the name of your account. For example, to get your 
        gmail password you might use::

            $ pw gmail
            password: preview secretary eschew cobra

        The password generator is also capable of generating answers to the 
        security questions that are the bane of most websites these days. Simply 
        add the questions to your accounts file, and the password generator will 
        produce an unpredictable yet consistent response for each question. For 
        example::

            $ pw -q0 gmail
            name of elementary school: balaclava essence guildhall persimmon

        In addition, the password generator will output account information upon 
        request. It is a command line program, so you would just specify the 
        right command line options to have it print out the username, account 
        number, url, etc.::

            $ pw -A gmail
            username: derrickAsh
            email: derrick.ash@yahoo.com
            url: https://accounts.google.com

        The output can be produced in three different ways.

        The first is that it is simply displayed on standard output. It tries to 
        keep the secret information (such as the password and answers to the 
        security questions) secure by displaying it for a minute and then 
        erasing it. The program continues to run while the password is 
        displayed. To clear the password early, just kill the program by typing 
        Ctrl-C.

        The second way is to send it to the clipboard. For security reasons, the 
        clipboard is cleared after a minute.

        Finally, the password generator can output the information by mimicking 
        the keyboard and sending it to active window. This is very powerful if 
        you configure your window manager to run **pw** because it makes it 
        possible to login to websites and such with a single keystroke.

        Security
        ++++++++
        The accounts file is a simple ASCII file that contains somehwat 
        sensitive information.  From this file one could infer the existence of 
        an account and would have some identifying information such as the 
        username and account number, but the passwords themselves are not 
        contained in the file, only the parameters of the passwords (how many 
        characters, the alphabet used, etc).  Because the file is somewhat 
        sensitive, it is recommended that it should be readable only by the 
        user. 

        It is possible to generate passwords for accounts that are not described 
        in the accounts file. As such, these 'stealth' accounts are more secure 
        since no information is retained that refers to these accounts. To 
        generate a password or pass phrase for such an account you would simply 
        give the name of the account on the command line. For example::

            pw my-secret-account

        You would need to remember the name of the account precisely. If you 
        give even a slightly different account name you will get a different 
        password.  In this case **pw** generates a password with the default 
        settings, which is actually a 4 word pass phrase, which most websites 
        reject.  You can indicate that **pw** should generate a actual password 
        by giving the name of a template.  A template is simply a named 
        collection of attributes that specify how to generate the password. You 
        may configure as many templates as you wish.  By default, **pw** comes 
        with four templates, =words, =chars, =master, and =extreme.  You can 
        generate a password (a collection of characters) instead of a pass 
        phrase (a collection of words) with::

            pw -d =chars my-secret-account

        More on Security
        ++++++++++++++++
        The password generator inherits the security policies of GPG. It is 
        important to recognize that any weakness in your GPG security policy 
        could result in your passwords being exposed. For example, if you enter 
        your GPG pass phrase into your agent and it is retained while you walk 
        away from your computer, then someone could use this program to access 
        all of your passwords (with access to your accounts file, they would 
        have everything they needed to know to break into each of your 
        accounts).  Thus, it is important to both carefully consider your use of 
        the GPG agent and it's password retention time. It is also important 
        that you dutifully use screen locking when you walk away from your 
        computer.

        How it Works
        ++++++++++++
        A secret such as a password or the answer to a security question starts 
        out as the simple stringing together of a few things. The password for 
        an account starts off as the combination of the account name, the 
        version, and the master password. For security questions, the question 
        itself is added in.  This combined string is then hashed into a very 
        long number.  Even the smallest change in any of the components used to 
        create it results in a very different hash. The hash is then mapped into 
        pass phrases or passwords with your choice of words or characters.  As 
        long the master password is kept secure, this approach is very safe.  
        Even knowing the algorithm and having access to the source code of the 
        **pw** program would not allow someone to predict your passwords.

        Getting Started
        +++++++++++++++
        Before using **pw** you must have a GPG identity (a public/private key 
        pair tagged to an email account). In addition, it is recommended that 
        you run gpg-agent. Then you must create your accounts and master 
        password file.  To do so, run::

            pw -i <gpg-id>

        For example, if your GPG identity is linked to derrickAsh@gmail.com, 
        then use:: 

            pw -i derrickAsh@gmail.com

        The creates two files if they do not already exist, 
        ~/.config/pw/master.gpg and ~/.config/pw/accounts. Of the two, the 
        master.gpg file is encrypted. To make it easy to change it, it is 
        recommended that you download and install the gpg plugin for vim, which 
        can be found at http://www.vim.org/scripts/script.php?script_id=3645. 
        The file you will download is named gnupg.vim, simply move it into 
        ~/.vim/plugin. Once you have done this, edit the file with vim or gvim. 
        It should ask you for the GPG passphrase associated with the GPG 
        identity you specified. Once you have entered it you can edit the file. 

        Then if desired, you can edit the accounts file and add an account. See 
        'man 5 pw' for information about all of the fields that **pw** uses. For 
        example, to add you gmail and bank accounts, you would add something 
        like the following to your accounts file::

            accounts = {{
                <skip over the templates at the start>
                "chase": {{
                    'template': "=chars",
                    'master': "derrick",
                    'username': "derrickash",
                    'account': "6478-4789874",
                    'email': "derrickAsh@gmail.com",
                    'url': "https://chaseonline.chase.com",
                }},
                "gmail": {{
                    'template': "=words",
                    'username': "derrickAsh",
                    'email': "derrick.ash@yahoo.com",
                    'url': "https://accounts.google.com",
                    'security questions': [
                        "name of elementary school",
                    ],
                    'master': 'derrick',
                    'window': [
                        'Google Accounts*',
                        'Gmail*',
                    ],
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},
            }}

        These fields are described in detail in pw(5).

        OPTIONS
        =======
        -p, --password          Output the password (default if nothing else is 
                                specified).
        -n, --username          Output the username.
        -a, --account-number    Output the account number.
        -e, --email             Output the email associated with this account.
        -u, --url               Output the website address.
        -q <N>, --question <N>  Output the answer to security question *N*.
        -r, --remarks           Output remarks.
        -A, --all               Output everything above except the secrets (the 
                                password and the answers to the security 
                                questions).

        -c, --clipboard         Write output to clipboard rather than stdout.
        -t, --autotype          Mimic a keyboard to send output to the active 
                                window rather than stdout. In this case any 
                                command line arguments that specify what to 
                                output are ignored and the *autotype* entry 
                                directs what is to be output.

        -f <str>, --find <str>  List any account that contains the given string 
                                in its ID.
        -s <str>, --search <str>
                                List any account that contains the given string 
                                in {search_fields}, or its ID.

        -d <template>, --default-template <template>
                                Template to use if account is not found.
        -l, --list-templates    List available templates (only pure templates 
                                are listed, not accounts, even though accounts 
                                can be used as templates)

        -w <secs>, --wait <secs>
                                Wait this log before clearing the secret (use 
                                0 to disable clearing).

        -i <GPG-ID>, --init <GPG-ID>
                                Initialize the master password and accounts 
                                files in ~/.config/pw (but only if they do not 
                                already exist).

        -h, --help              Show a brief summary of available command line
                                options.

        DIAGNOSTICS
        ===========

        A log file is created in ~/.config/pw/log (the location of this file can 
        be specified in the *logfile* variable in the accounts file).

        SEE ALSO
        ========
        pw(3), pw(5)
    }"""
}

# API Manpage {{{1
apiManpage = {
    'name': 'pw',
    'sect': '3',
    'contents': r'''{
        ====
         pw
        ====

        ------------------
        password generator
        ------------------

        :Author: Ken Kundert <pw@nurdletech.com>
        :Date: {date}
        :Version: {version}
        :Manual section: 3

        .. :Copyright: public domain
        .. :Manual group: Utilities

        DESCRIPTION
        ===========
        The API to **pw** will be simply demonstrated by example. Here is 
        a program that mounts a series of directories. It uses *sudo*, which 
        requires a password the first time it is run, and it runs *mount* for 
        each directory, which requires a password each time it is run.

        Here is the *mountall* script::

            #!/bin/env python3

            from fileutils import expandPath, makePath, execute, pipe, ExecuteError
            from sys import exit
            from os import fork
            from time import sleep
            from pw import Password, PasswordWriter, PasswordError

            shares = {{
                'music': 'audio',
                'lib/passwords': True,
                'business': True,
                'consulting': True,
                'home': True,
                'personal': True,
                'photos': True,
                'profession': True,
                'reference': True,
            }}

            def run_cmd_with_password(cmd):
                try:
                    if (fork()):
                        execute(cmd)
                    else:
                        sleep(1)
                        writer.write_autotype()
                        writer.process_output()
                        exit()
                except PasswordError as err:
                    exit(err.message)

            try:
                # Open the password generator
                pw = Password()
                pw.read_accounts()
                writer = PasswordWriter('t', pw)

                # Clear out any saved sudo credentials. This is needed so that 
                # we can be sure the next run of sudo requests a password.  
                # Without this, the password that is autotyped may be exposed.
                execute('sudo -K')

                # Get the login password
                pw.get_account('login')

                # Run sudo so that it requests the password and sets the 
                # credentials. In this way the subsequent calls to sudo will not 
                # request a password.
                run_cmd_with_password('sudo true')

                # Get the Samba password
                pw.get_account('dgc21')

                for src, dest in shares.items():
                    if dest == True:
                        dest = src
                    absdest = expandPath(makePath('~', dest))
                    status, stdout = pipe('mountpoint -q %s' % absdest, accept=(0,1))
                    if status:
                        print("Mounting %s to %s" % (src, absdest))
                        run_cmd_with_password('sudo mount %s' % (absdest))
                    else:
                        print("Skipping %s (already mounted)" % (dest))
            except KeyboardInterrupt:
                exit('Killed by user')
            except ExecuteError as err:
                exit(err.text)

        The program starts by instantiating both the *Password* and the 
        *PasswordWriter* class. The *Password* class is responsible for 
        generating the password and *PasswordWriter* gets it to the user. In 
        this case the autotype facility of *PasswordWriter* is used to mimic the 
        keyboard.  When instantiating the *PasswordWriter* you must specify the 
        intended output. Use ``output='t'`` for autotype, ``output='c'`` for 
        clipboard, and ``output='s'`` for standard output.

        SEE ALSO
        ========
        pw(1), pw(5)
    }'''
}

# Configuration Files Manpage {{{1
configManpage = {
    'name': 'pw',
    'sect': '5',
    'contents': r'''{
        ====
         pw
        ====

        ------------------
        password generator
        ------------------

        :Author: Ken Kundert <pw@nurdletech.com>
        :Date: {date}
        :Version: {version}
        :Manual section: 5

        .. :Copyright: public domain
        .. :Manual group: Utilities

        DESCRIPTION
        ===========
        **pw** requires two files to operate. The master password file and the 
        accounts file. You may optionally add a third file that gives the 
        dictionary used when creating pass phrases.


        Master Password File
        ++++++++++++++++++++
        The master password file is named '~/.config/pw/master.gpg'. It is 
        encrypted with the GPG ID that you specified when you ran 'pw --init'.
        It is a Python file that contains five variables. To be able to edit 
        conveniently it is recommended that you add the gnupg plugin to vim 
        (download it from 
        ``http://www.vim.org/scripts/script.php?script_id=3645`` and copy it 
        into ~/.vim/plugin).

        dict_hash
        ~~~~~~~~~
        This is a hash of the file that contains the words used when generating 
        pass phrases. You should not change this value. It is used to warn you 
        if somehow your words file is changed or corrupted, which would corrupt 
        your pass phrases.

        secrets_hash
        ~~~~~~~~~~~~
        This is a hash of the file that contains the code used when generating 
        the hash and converting it to a password of pass phrase.  It is used to 
        warn you that the secrets code has changed, presumably when the program 
        itself was updated.  If this occurs you should verify that the passwords 
        it generates are the same. If not, you should not use the updated 
        version of the program. If they are the same, you should update the 
        *secrets_hash*. Do this by moving the existing *master.gpg* file out of 
        the way, generating a new one with *pw -i*, copying the new 
        *secrets_hash* to the original file, and then moving it back to its 
        original location of *~/.config/pw/master.gpg*.

        passwords
        ~~~~~~~~~
        This is a dictionary that gives your master passwords. Each entry is 
        a pair of the password ID and then password itself. For example::

            passwords = {{
                'derrick': """hush puppie""",
                'derrick debbie': """lounge lizard""",
            }}

        Generally you will never have to type these passwords again, so there is 
        little reason not to make them long and very random. There are no limits 
        on the length of the passwords or the characters they may contain, so 
        you can go wild. For example, using your default master password you 
        could use **pw** to generate new master passwords::

            $ pw -d =extreme derrick
            password: [Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|

        You can then use that string as the master password. Notice that this 
        string contains quote characters, meaning that you will have to embed it 
        in triple quotes to avoid trouble::

            passwords = {{
                'derrick': """[Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|""",
            }}

        Of course it is not necessary to go to these extremes. Your password 
        must just not be guessable. One reason not to go to such extremes is if 
        you need to share a master password with a friend while talking over the 
        phone.  In this case, using the =master template to generate a simple 
        but long pass phase is much preferred::

            $ pw -d =master "derrick debbie"
            password: impulse nostril double irony conflate rookie posting blind

        Then your passwords entry becomes::

            passwords = {{
                'derrick': """[Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|""",
                'derrick debbie': """impulse nostril double irony conflate rookie posting blind""",
            }}

        This approach of using the default password to generate your master 
        passwords, each of which has a very predictable name, can make it 
        possible for you to reconstruct your master password file if you happen 
        to lose it. To do so, you will need to keep a copy of the default 
        password in a safe place (along with your master GPG keys in a safe 
        deposit box, for example). Of course, you really should save both 
        the master password and accounts file in a safe place because they 
        contain additional information that is used to generate your passwords 
        (account names, versions, security quesitons, etc.). You should be aware 
        that these tend to change with time and so your saved files can quickly 
        go out of date.  However, if your follow a practice of using very  
        systematic naming strategies for master passwords, accounts, versions, 
        and the like, you can dramatically increase the chances of being able to 
        retrieve your passwords from an old master password and accounts file.

        You are free to name your master passwords in any manner that pleases 
        you. One reasonable approach is to name them after the people that will 
        use them. Thus in the example above, Derrick has one key he uses for his 
        own accounts and another for accounts he shares with Debbie. When it 
        comes time to outdate a master password, simply add '(deprecated 
        <date>)' to the end of the master password name, where <date> is 
        replaced with the date that the password was deprecated. When doing so,
        be sure to also change the name used in the *accounts* file so that the
        existing passwords do not change.

        Using this approach your master password file might look like this::

            passwords = {{
                'derrick': """[Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|""",
                'derrick (deprecated 120301)': """2HG}},t`ci/+Vydj)z_Q*Go,a-f- qrc3YVChK`}}6QV5S_B*@>GwC0*5Bv9>kaTiL""",
                'derrick debbie': """impulse nostril double irony conflate rookie posting blind""",
            }}

        default_password
        ~~~~~~~~~~~~~~~~
        The ID of the default master password::

            default_password = "derrick"

        This password will be used when an account does not explicitly specify 
        a master password. It is recommended you set the default master password 
        once and after that never change it, because if you do, the passwords 
        that rely on it will also change. You are given a very secure default 
        password when your master password file is initially created for you. It 
        is recommended that you never change it.

        Using a value of None for default_password disables the default 
        password, forcing you to always specify a master password.

        password_overrides
        ~~~~~~~~~~~~~~~~~~
        A dictionary that contains passwords for specific accounts. These 
        passwords will be produced rather than the generated passwords. For 
        example::

            password_overrides = {{
                'yahoo': 'lollipop',
                'nytimes': 'excelsior',
            }}

        Password overrides are generally used in two situations. First is when 
        a password is provided to you (you have no or limited ability to choose 
        it). Second is for the accounts you have not yet migrated to the new 
        passwords generated by **pw**.

        Accounts File
        +++++++++++++

        The accounts file is '~/.config/pw/accounts'. It starts out defining 
        some character sets. You are free to modify these but there is generally 
        no reason to. They are there to help you create alphabets for your 
        passwords. A function exclude() is also defined, which allow you to 
        create an alphabet by removing characters from the preexisting ones.  
        You can add characters simply summing them.

        The accounts file is a Python file that must contain two variables.

        logfile
        ~~~~~~~

        Specifies the location of the location of the log file. If not given, it 
        defaults to '~/.config/pw/log'.

        accounts
        ~~~~~~~~

        A dictionary where each entry represents either an account or 
        a template. By convention, templates have an ID that starts with '='.

        Templates are used to limit the information you need to give in an 
        account. You just create or use a template that has the desired base 
        information. Then when creating an account, you can refer to the 
        template and only specify the fields that need to be unique for that 
        account. The template for an account can be another account or 
        a template. In this way templates are just accounts that are not
        associated with any particular account in the real world.  For example::

            accounts = {{
                "=words": {{  # typically used for linux pass phrases
                    'type': 'words',
                    'num-words': 4,
                    'autotype': "{{password}}{{return}}",
                }},
                "gmail": {{
                    'template': "=words",
                    'username': "derrickAsh",
                    'url': "https://accounts.google.com",
                    'master': 'derrick',
                    'window': [
                        'Google Accounts*',
                        'Gmail*',
                    ],
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},
                ...
            }}

        In this example '=words' is specified as the template for 'gmail'. Thus 
        any field specified in '=words' that is not specified in 'gmail' is 
        inherited by 'gmail'. Any field specified in 'gmail' overrides the field 
        with the same name from '=words' when using 'gmail'. This process of 
        inheritance can chain through any number of templates or accounts. For 
        example, you can create another account, say 'gmail-work' that uses 
        'gmail' as a template but overrides the 'username'.

        Each dictionary in accounts may contain a number of fields that are 
        described next. When first created the accounts dictionary comes with 
        some useful templates and an example account entry that is commented 
        out. Feel free to modify the templates and delete the example account.

        username
        ~~~~~~~~
        A string containing the username for the account.

        account
        ~~~~~~~
        A string containing the account number for the account.

        email
        ~~~~~
        A string containing the email address associated with the account.

        url
        ~~~
        A string containing the web address of the account.

        security questions
        ~~~~~~~~~~~~~~~~~~
        A list of strings containing the security questions they force you to 
        answer. The string does not need to contain the question verbatim, 
        a shortened version that is sufficient for you to identify which of the 
        questions you need to provide the answer to is enough.  For example, 
        a typical list of security questions might be::

            'security questions': [
                "first teacher's name",
                "name of elementary school",
            ],

        When initially giving the answers to these questions, you will have to 
        select the questions you will answer, enter them into the accounts file, 
        then get the answers by running **pw**, and then copying the answers 
        into the webpage for your account. In this way, your answers will be 
        quite unpredictable, even to those that know you well.

        remarks
        ~~~~~~~
        A string containing any relevant remarks about the account.

        window
        ~~~~~~
        This may be either a glob string or a list of glob strings that match 
        the title of the webpage used to enter the username/password for the 
        account. This is used to determine which account should be used if no 
        account name is given on the command line.

        This enables you to set up a hotkey, such as Alt-P, to run 'pw -t', 
        which will identify which account to use from the active window 
        title and then use the *autotype* field to log you in.

        When using commands from shell the title of the window is generally 
        unaffected by the command that is running. However, you can write 
        a simple script that first sets the window title and then runs the 
        command. Here is an example of such a script for mutt::

            #!/bin/sh
            xdotool getactivewindow set_window --name "Mutt"
            mutt

        autotype
        ~~~~~~~~
        A string containing a login script when autotyping (when the -t or 
        --autotype command line option is specified).  The script consists of 
        characters that will be emitted verbatim and codes that specify actions 
        to take.  Primarily the action is to replace the code with a character, 
        a field from the account, or a secret. But the sleep action can be used 
        to cause a pause in the typing. The following actions are supported:

        |   {{username}}      Replaced with the username for the account.
        |   {{account}}       Replaced with the account number for the account.
        |   {{url}}           Replaced with the URL for the account.
        |   {{email}}         Replaced with the email address for the account.
        |   {{remarks}}       Replaced with the remarks for the account.
        |   {{password}}      Replaced with the password for the account.
        |   {{question *N*}}    Replaced with security question *N* (*N* is an integer).
        |   {{answer *N*}}      Replaced with the answer to security question *N* (*N* is an integer).
        |   {{sleep *S*}}       Typing is paused for *S* seconds (*S* a real number)
        |   {{tab}}           Replaced with a tab.
        |   {{return}}        Replaced with newline.

        The default autotype script is 
        "{{username}}{{tab}}{{password}}{{return}}"

        template
        ~~~~~~~~
        A string containing the ID of the template for this account (explained 
        above).

        master
        ~~~~~~~~
        A string containing the ID of the master password for this account.
        It is highly recommended that each account explicitly declare its master 
        password (perhaps through a template). That way existing passwords do 
        not change if you were to change your default master password.

        type
        ~~~~
        The type of password to generate. Should be either 'words' (default) to 
        generate pass phrases or 'chars' to generate passwords.

        num-words
        ~~~~~~~~~
        The number of words to use in the pass phrase (when 'type' is 'words').

        num-chars
        ~~~~~~~~~
        The number of characters to use in the passwords (when 'type' is 
        'chars').

        alphabet
        ~~~~~~~~
        A string containing the characters to use when creating a password (when 
        'type' is 'chars'). The default alphabet consists of the standard upper 
        and lower case letters along with the digits.

        prefix
        ~~~~~~
        A string whose contents are added to the beginning of a password (when 
        'type' is 'chars').

        suffix
        ~~~~~~
        A string whose contents are added to the end of a password (when 'type' 
        is 'chars').

        Words File
        ++++++++++
        The words file is '~/.config/pw/words'. The use of this file is 
        optional.  **pw** has its own words that it uses if you do not provide 
        a file yourself. It should contain a large number of words (thousands), 
        one word per line. The more words your file contains, the more secure 
        your pass phrases are, however anymore than 65,536 are not used.

        Do not change this file once you have started creating passwords, and be 
        sure to back it up. Any change to this file will cause the generated 
        pass phrases to change, which means you will not be able to use **pw** 
        to login to existing accounts that use pass phrases.

        EXAMPLE
        =======

        Master Password File
        ++++++++++++++++++++

        Here is a representative master password file (~/.config/pw/master.gpg)::

            dict_hash = "d9aa1c08e08d6cacdf82819eeb5832429eadb95a"
            passwords = {{
                'derrick': "e9a7a4246a6a95f179cd4579e6f9cb69",
                'derrick debbie': "60b56e021118ca2a261f405e15ac0165",
                'default': """[Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|""",
            }}
            default_password = 'default'
            password_overrides = {{
                'yahoo': 'lollipop',
                'nytimes': 'excelsior',
            }}


        Accounts File
        +++++++++++++

        Here is a representative accounts file (~/.config/pw/accounts)::

            # Account Information
            accounts = {{
                # Templates
                "=words": {{  # typically used for linux pass phrases
                    'type': 'words',
                    'num-words': 4,
                    'autotype': "{{password}}{{return}}",
                }},
                "=chars": {{  # typically used for web passwords
                    'type': 'chars',
                    'num-chars': 12,
                    'alphabet': alphanumeric + punctuation,
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},

                # Accounts
                "login": {{
                    'template': "=words",
                }},
                "mail": {{
                    'template': "login",
                    'window': 'Mutt *',
                }},
                "ssh": {{
                    'template': "login",
                    'version': 'ssh',
                    'window': 'tcsh: *',
                }},
                "bank": {{
                    'template': "=chars",
                    'username': "derrickash",
                    'email': "derrickAsh@gmail.com",
                    'url': "https://chaseonline.chase.com",
                    'account': "1987-357836",
                    'window': [
                        'CHASE Bank*',
                        'Chase Online*',
                    ],
                }},
                "gmail": {{
                    'template': "=words",
                    'username': "derrickAsh",
                    'email': "derrick.ash@yahoo.com",
                    'url': "https://accounts.google.com",
                    'security questions': [
                        "first teacher's name",
                        "name of elementary school",
                    ],
                    'window': [
                        'Google Accounts*',
                        'Gmail*',
                    ],
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},
                "yahoo": {{
                    'username': "derrickAsh",
                    'email': "derrickAsh@gmail.com",
                    'url': "https://login.yahoo.com",
                    'window': 'Sign into Yahoo!*',
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},
                "nytimes": {{
                    'username': "derrickAsh",
                    'email': "derrickAsh@gmail.com",
                    'url': "https://myaccount.nytimes.com/auth/login",
                    'window': '*The New York Times*',
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},
                "consumer-reports": {{
                    'master': 'derrick debbie',
                    "60b56e021118ca2a261f405e15ac0165",
                    'username': "derrickAndDave",
                    'url': "https://ec.consumerreports.org/ec/myaccount/login.htm",
                    'window': 'My account login*',
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},
            }}

        SEE ALSO
        ========
        pw(1), pw(3)
    }'''
}

# Generate restructured text {{{1
def write(genRST=False):
    for each in [programManpage, apiManpage, configManpage]:
        rst = dedent(each['contents'][1:-1]).format(
            date=date
          , version=version
          , search_fields=', '.join(search_fields)
        )

        # generate reStructuredText file (only used for debugging)
        if genRST:
            with open('%s.%s.rst' % (each['name'], each['sect']), 'w') as f:
                f.write(rst)

        # Generate man page
        print("generating %s.%s" % (each['name'], each['sect']))
        with open('%s.%s' % (each['name'], each['sect']), 'w') as f:
            f.write(publish_string(rst, writer=manpage.Writer()).decode())

if __name__ == '__main__':
    write(True)

# vim: set sw=4 sts=4 tw=80 formatoptions=ntcqwa12 et spell: 