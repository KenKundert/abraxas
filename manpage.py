#!/usr/bin/env python

# Abraxas Collaborative Password Utility Documentation
#
# Converts a restructured text version of the manpages to nroff.

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
from docutils.core import publish_string
from docutils.writers import manpage
from textwrap import dedent
from abraxas.prefs import SEARCH_FIELDS
from abraxas.version import DATE, VERSION

# Program Manpage {{{1
PROGRAM_MANPAGE = {
    'name': 'abraxas',
    'sect': '1',
    'contents': r"""{
        =========
         abraxas
        =========

        ------------------------------
        collaborative password utility
        ------------------------------

        :Author: Kale and Ken Kundert <abraxas@nurdletech.com>
        :Date: {date}
        :Version: {version}
        :Manual section: 1

        .. :Copyright: Kale and Ken Kundert
        .. :Manual group: Utilities

        SYNOPSIS
        ========
        **abraxas** [*options*] [*account*]

        OPTIONS
        =======
        -P, --password          Output the password (default if nothing else is 
                                specified).
        -N, --username          Output the username.
        -Q <N>, --question <N>  Output the answer to security question *N*.
        -A, --account-number    Output the account number.
        -E, --email             Output the email associated with this account.
        -U, --url               Output the website address.
        -R, --remarks           Output remarks.
        -i, --info              Output all account information except the 
                                secrets (the password and the answers to the 
                                security questions).
        -a, --all               Same as --info except also output the password.

        -q, --quiet             Disable all non-essential output.
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

        -S, --stateless         Do not use master password or accounts file.
        -T <template>, --template <template>
                                Template to use if account is not found.

        -b, --default-browser   Open account in the default browser.
        -B <browser>, --browser <browser>
                                Open account in the specified browser.

        -n, --notify            Output messages to notifier.

        -l, --list              List available master passwords and templates 
                                (only pure templates are listed, not accounts, 
                                even though accounts can be used as templates)

        -w <secs>, --wait <secs>
                                Wait this log before clearing the secret (use 
                                0 to disable clearing).

        --archive               Archive all the secrets to 
                                ~/.config/abraxas/archive.gpg.
        --changed               Identify all the secrets that have changed since 
                                last archived.

        -I <GPG-ID>, --init <GPG-ID>
                                Initialize the master password and accounts 
                                files in ~/.config/abraxas (but only if they do 
                                not already exist).

        -h, --help              Show a brief summary of available command line
                                options.

        DIAGNOSTICS
        ===========

        A log file is created in ~/.config/abraxas/log (the location of this 
        file can be specified in the *log_file* variable in the accounts file).

        DESCRIPTION
        ===========
        Abraxas is password utility that can store or generate your passwords 
        and produce them from the command line. It can also be configured to 
        autotype your username and password into the current window so that you 
        can log in with a simple keystroke. 

        Abraxas is capable of generating two types of passwords, character based 
        (pass words) or word based (pass phrases).  Pass phrases are generally 
        preferred if you have a choice, but many websites will not take them. 
        The benefit of pass phrases is that they are relatively easy to remember 
        and type, and they are very secure. The pass phrases generated by 
        Abraxas generally consist of four words, each word is drawn from 
        a dictionary of 10,000 words.  Thus, even if a bad guy knew that four 
        lower case words were being used for your pass phrase, there are still 
        10,000,000,000,000,000 possible combinations for him to try (this 
        represents a minimum entropy of 53 bits).  Using six words results in 80 
        bits of entropy, which meets the threshold recommended by NIST for the 
        most secure pass phrases. For more on this, see 'How Much Entropy is 
        Enough' below.

        For another perspective on the attractiveness of pass phrases, see 
        `<http://xkcd.com/936/>`_.

        Unlike password vaults, Abraxas produces a highly unpredictable password 
        from a master password and the name of the account for which the 
        password is to be used. The process is completely repeatable. If you 
        give the same master password and account name, you will get the same 
        password. As such, the passwords do not have to be saved; instead they 
        are regenerated on the fly.

        As a password generator, Abraxas provides three important advantages 
        over conventional password vaults.  First, it allows groups of people to 
        share access to accounts without having to securely share each password.  
        Instead, one member of the group creates a master password that is 
        securely shared with the group once. From then on any member of the 
        group can create a new account, share the name of the account, and all 
        members will know the password needed to access the account. The second 
        advantage is that it opens up the possibility of using high-quality 
        passwords for stealth accounts, which are accounts where you remember 
        the name of the account but do not store any information about even the 
        existence of the account on your computer.  With Abraxas, you only need 
        to remember the name of the account and it will regenerate the password 
        for you. This is perfect for your TrueCrypt hidden volume password.  
        Finally, by securely storing a small amount of information, perhaps on 
        a piece of paper in your safe-deposit box, you can often recover most if 
        not all of your passwords even if you somehow lose your accounts file.  
        You can even recover passwords that were created after you created your 
        backup. This is because Abraxas combines the master password with some 
        easily reconstructed information, such as the account name, to create 
        the password. If you save the master password, the rest should be 
        recoverable.

        To use it, one creates a file that contains information about each of 
        his or her non-stealth accounts.  Among that information would be 
        information that controls how the passwords are generated. This file is 
        generally not encrypted, though you can encrypt it if you like).  
        Another file is created that contains one or more master passwords.  
        This file is always GPG encrypted.

        The intent is for these files to not include the passwords for your 
        accounts.  Rather, the passwords are regenerated when needed from the 
        account information and from the master password. This makes it easy to 
        share passwords with others without having to pass the passwords back 
        and forth.  It is only necessary to create a shared master password in 
        advance. Then new passwords can be created on the fly by either party.

        Basic Use
        +++++++++
        To generate a password for an account that exists in your accounts file, 
        you would use::

            abraxas <account>

        where <account> is the name of your account. For example, to get your 
        gmail password you might use::

            $ abraxas gmail
            PASSWORD: preview secretary eschew cobra

        The $ represents the shell prompt, you do not type it.

        The password generator is also capable of generating answers to the 
        security questions that are the bane of most websites these days.  
        Simply add the questions to your accounts file and the password 
        generator will produce an unpredictable yet consistent and easily 
        communicated response for each question.  For example::

            $ abraxas -q0 gmail
            name of elementary school: balaclava essence guildhall persimmon

        There is a very good reason not to actually provide your personal 
        information as a response to these questions. Often it is friends and 
        family members that are the most likely to attempt to surreptitiously 
        access your account. As with most crime, it comes down to opportunity 
        and motive. The opportunity comes from the fact that they know you and 
        so are more likely to know the information, like the answers to these 
        security questions, that allows them access to your account.  The motive 
        generally comes eventually. It is hard to live one's life without 
        angering a friend or family member at some point, and then they may feel 
        justified in helping themselves to your accounts.

        Abraxas outputs account information upon request.  It is a command line 
        program, so you just specify the right command line options to have it 
        print out the username, account number, url, etc.::

            $ abraxas -i gmail
            USERNAME: derrickAsh
            EMAIL: derrick.ash@yahoo.com
            URL: https://accounts.google.com

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
        the keyboard and 'typing' it to active window.  This is referred to as 
        'autotype'.

        Account Discovery
        +++++++++++++++++
        If no account is specified, Abraxas examines the window title and from 
        it tries to determine which account to use. In its most simple form 
        window titles can be specified in the accounts, and the account with the 
        matching title is used. Multiple title strings can be associated with 
        each account, and those strings support globbing. In addition, Abraxas 
        can sometimes recognize components of the window title, components such 
        as the URL, the protocol, etc., and it can compare those component to 
        fields in the account to determine which account to use.  In particular, 
        Abraxas comes with the ability to recognize the title components created 
        by 'Hostname in Titlebar', an add-on to Firefox that puts the URL and 
        protocol in the title bar (with Chrome, use 'Url in Title').

        If the title matches multiple accounts, a dialog box opens with the list 
        of each of those accounts. Use the up or *k* and down or *j* keys to 
        navigate to the account you want and select it with *Enter* or *Return*.  
        You can cancel using *Esc*.

        The combination of autotype and account discovery is very powerful if 
        you configure your window manager to run Abraxas because it makes it 
        possible to login to websites and such with a single keystroke.

        Autotype can sometimes be a bit problematic. Some programs can 
        occasionally stubbornly ignore particular autotyped characters, 
        particularly $ and newline. This can occur with Firefox, whereas in 
        those cases it did not occur with Chrome. If this affects you, you 
        might want to simply remove $ from your character set for your 
        passwords (newline is not as problematic as it generally occurs last, 
        and so can be added by hand).

        Security
        ++++++++
        The accounts file can be a simple ASCII file that contains somewhat 
        sensitive information.  From this file one could infer the existence of 
        an account and would have some identifying information such as the 
        username and account number, but the passwords themselves are not 
        contained in the file, only the parameters of the passwords (how many 
        characters, the alphabet used, etc).  Because the file is somewhat 
        sensitive, it is recommended that it should be readable only by the 
        user. If you are uncomfortable with this level of protection, you can 
        further protect the accounts file by encrypting it. To do so, run::

            $ cd ~/.config/abraxas
            $ gpg --armor --encrypt --recipient <your-gpg-id> accounts
            $ shred -u accounts

        In some cases the mere existence of this file, even though encrypted, 
        may be problematic. Once discovered, authorities may compel you hand 
        over the decryption keys, which would expose the existence of all of 
        your accounts and provide access to each of them.

        It is possible to generate passwords for accounts that are not described 
        in the accounts file. As such, these 'stealth' accounts are more secure 
        since no information is retained that refers to these accounts; they 
        provide plausible deniability. To generate a password or pass phrase for 
        such an account you would simply give the name of the account on the 
        command line. For example::

            $ abraxas my-secret-account
            warning: account 'my-secret-account' not found.
            PASSWORD: apologist imprint epigram return

        You would need to remember the name of the account precisely. If you 
        give even a slightly different account name you will get a different 
        password.  In this case Abraxas generates a password with the default 
        settings, which is actually a 4 word pass phrase, which most websites 
        reject.  You can indicate that Abraxas should generate an actual 
        password by giving the name of a template.  A template is simply a named 
        collection of attributes that specify how to generate the password. You 
        may configure as many templates as you wish.  By default, Abraxas comes 
        with eight templates:

        =words:
            A sequence of random English words. The default is to use 4 words, 
            which provides 53 bits of entropy.
        =chars:
            A sequence of random letters (upper and lower case), digits and 
            symbols. The default is to use 12 characters, which provides 79 bits 
            of entropy.
        =pin:
            A sequence of random digits. The default is to use 4 digits, which 
            provides 13 bits of entropy.  This is typically used for PIN 
            numbers.
        =num:
            A sequence of random digits. The default is to use 8 digits, which 
            provides 26 bits of entropy.  This is also used for PIN numbers, but 
            it provides better security.
        =word:
            A single random word. Chosen from a list of 10,000 words, this is 
            equivalent to a 4 digit PIN, but is easier to remember. It provides 
            13 bits of entropy.
        =anum:
            A sequence of easily distinguishable random letters. The letters may 
            be both upper and lower case, but will not include any letters that 
            are easily confused with other letters or digits (Il1O0). Typically 
            used for web passwords.  The default is to use 12 characters, which 
            provides 78 bits of entropy.
        =master:
            A sequence of random English words. The default is to use 8 words, 
            which provides 106 bits of entropy.
        =extreme:
            A sequence of random letters (upper and lower case), digits and 
            symbols. The default is to use 64 characters, which provides 420 
            bits of entropy.

        You can generate a pass word (a collection of characters) instead of 
        a pass phrase (a collection of words) for a stealth account with::

            $ abraxas -T =anum my-secret-account
            warning: account 'my-secret-account' not found.
            PASSWORD: Rkybp9EFXLu4

        It is possible to take this one step further. Specifying the ``-S`` or 
        ``--stateless`` command line option instructs Abraxas to avoid using any 
        saved information when generating the password.  In this situation, you 
        must give both the account name (on the command line) and the master 
        password. As long as you use a master password or pass phrase that is 
        memorable for you but difficult for everyone else to guess, you should 
        be reasonably safe from someone figuring out your password even if they 
        have full access to your private GPG keys and your Abraxas files. For 
        example::

            $ abraxas --stateless my-secret-account
            Provide master password for account 'my-secret-account'.
            Password: my-secret-master-passphrase
            PASSWORD: toehold physical illusion washroom

        When running in stateless mode you do not have access to any templates 
        you may have created in your accounts file because that file is ignored, 
        but you have access to the predefined templates described above::

            $ abraxas -S -T =anum my-secret-account
            Provide master password for account 'my-secret-account'.
            Password: my-secret-master-passphrase
            PASSWORD: LfCkPFygucg9

        GPG Security
        ++++++++++++
        Abraxas inherits the security policies of GPG.  It is important to 
        recognize that any weakness in your GPG security policy could result in 
        your passwords being exposed. For example, if you enter your GPG pass 
        phrase into your agent and it is retained while you walk away from your 
        computer, then someone could use this program to access all of your 
        passwords (with access to your accounts file, they would have everything 
        they needed to know to break into each of your accounts).  Thus, it is 
        important to both carefully consider your use of the GPG agent and it's 
        password retention time. It is also important that you dutifully use 
        screen locking when you walk away from your computer.

        Archiving
        +++++++++
        There are features in Abraxas that could allow you to inadvertently and 
        unknowingly change the passwords that are generated for an account.  For 
        example, changing the master password would change the passwords for all 
        accounts that linked to that master password. Similarly, changing the 
        definition of a template would change the passwords for all accounts 
        that employ that template. To avoid this, Abraxas allows you to quickly 
        tell whether the passwords for any known account has changed. To use 
        this feature, you must first archive your secrets.

        You generate an archive of the secrets for all of the known accounts 
        with::

            abraxas --archive

        The resulting archive is encrypted and saved in your settings directory 
        (~/.config/abraxas/archive.gpg). In addition, you can check your current 
        list of secrets against those in the archive with::

            abraxas --changed

        It is a good idea to do this when you have change your master password 
        or accounts files and when you have update your version of Abraxas.  
        Doing so will alert you to any unexpected changes. It is also 
        recommended that you always confirm you only see the changes you expect 
        before updating the archive.

        How it Works
        ++++++++++++
        A secret such as a password or the answer to a security question starts 
        out as the simple stringing together of a few things: the account name, 
        the version, and the master password.  For security questions, the 
        question itself is added as well.  This combined string is then hashed 
        into a very long number.  Even the smallest change in any of the 
        components used to create it results in a very different number.  The 
        number is then mapped into pass phrases or passwords with your choice of 
        words or characters.  As long the master password is kept secure, this 
        approach is very safe.  Even knowing the algorithm and having access to 
        the source code of the Abraxas program would not allow someone to 
        predict your passwords.

        Getting Started
        +++++++++++++++
        Before using Abraxas you must have a GPG identity (a public/private key 
        pair tagged to an email account). In addition, it is recommended that 
        you run gpg-agent (add 'gpg-agent' alone on a line into your 
        ~/.gnupg/gpg.conf file and then start the agent).  Then you must create 
        your accounts and master password file.  To do so, run::

            $ abraxas -I <gpg-id>

        For example, if your GPG identity is linked to derrickAsh@gmail.com, 
        then use:: 

            $ abraxas -I derrickAsh@gmail.com

        This creates two files if they do not already exist, 
        ~/.config/abraxas/master.gpg and ~/.config/abraxas/accounts. Of the two, 
        the master.gpg file is encrypted. If you would like the accounts file to 
        be encrypted as well, encrypt it now using::

            $ gpg --armor --encrypt --recipient <gpg-id> accounts

        To make it easy to change an encrypted file, it is recommended that you 
        download and install the gpg plugin for vim, which can be found at 
        http://www.vim.org/scripts/script.php?script_id=3645.  The file you will 
        download is named gnupg.vim, simply move it into ~/.vim/plugin.  Once 
        you have done this, edit the file with vim or gvim.  It should ask you 
        for the GPG pass phrase associated with the GPG identity you specified.  
        Once you have entered it you can edit the file. 

        Then if desired, you can edit the accounts file and add an account. See 
        'man 5 abraxas' for information about all of the fields that Abraxas 
        uses.  For example, to add your gmail and bank accounts, you would add 
        something like the following to your accounts file::

            accounts = {{
                <skip over the templates at the start>
                "chase": {{
                    'template': "=chars",
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
                    'window': [
                        'Google Accounts*',
                        'Gmail*',
                    ],
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},
            }}

        These fields are described in detail in abraxas(5).

        How Much Entropy is Enough
        ++++++++++++++++++++++++++

        A 4 word Abraxas password provides 53 bits of entropy, which seems like 
        a lot, but NIST is recommending 80 bits for your most secure passwords.  
        So, how much is actually required. It is worth exploring this question.  
        Entropy is a measure of how hard the password is to guess. Specifically, 
        it is the base two logarithm of the likelihood of guessing the password 
        in a single guess. Every increase by one in the entropy represents 
        a doubling in the difficulty of guessing your password. The actual 
        entropy is hard to pin down, so generally we talk about the minimum 
        entropy, which is the likelihood of an adversary guessing the password 
        if he or she knows everything about the scheme used to generate the 
        password but does not know the password itself.  So in this case the 
        minimum entropy is the likelihood of guessing the password if it is 
        known that we are using 4 space separated words as our pass phrase.  
        This is very easy to compute.  There are roughly 10,000 words in our 
        dictionary, so if there was only one word in our pass phrase, the chance 
        of guessing it would be one in 10,000 or 13 bits of entropy. If we used 
        a two word pass phrase the chance of guessing it in a single guess is 
        one in 10,000*10,000 or one in 100,000,000 or 26 bits of entropy.

        The probability of guessing our pass phrase in one guess is not our 
        primary concern. Really what we need to worry about is given 
        a determined attack, how long would it take to guess the password. To 
        calculate that, we need to know how fast our adversary could try 
        guesses. If they are trying guesses by typing them in by hand, their 
        rate is so low, say one every 10 seconds, that even a one word pass 
        phrase may be enough to deter them.  Alternatively, they may have 
        a script that automatically tries pass phrases through a login 
        interface.  Again, generally the rate is relatively slow.  Perhaps at 
        most the can get is 1000 tries per second. In this case they would be 
        able to guess a one word pass phrase in 10 seconds and a two word pass 
        phrase in a day, but a 4 word pass phrase would require 300,000 years to 
        guess in this way.

        The next important thing to think about is how your password is stored 
        by the machine or service you are logging into. The worst case situation 
        is if they save the passwords in plain text. In this case if someone 
        were able to break in to the machine or service, they could steal the 
        passwords. Saving passwords in plain text is an extremely poor practice 
        that was surprisingly common, but is becoming less common as companies 
        start to realize their liability when their password files get stolen. 
        Instead, they are moving to saving passwords as hashes.  A hash is 
        a transformation that is very difficult to reverse, meaning that if you 
        have the password it is easy to compute its hash, but given the hash it 
        is extremely difficult to compute the original password. Thus, they save 
        the hashes (the transformed passwords) rather than the passwords. When 
        you log in and provide your password, it is transformed with the hash 
        and the result is compared against the saved hash. If they are the same, 
        you are allowed in. In that way, your password is no longer available to 
        thieves that break in.  However, they can still steal the file of hashed 
        passwords, which is not as good as getting the plain text passwords, but 
        it is still valuable because it allows thieves to greatly increase the 
        rate that they can try passwords. If a poor hash was used to hash the 
        passwords, then passwords can be tried at a very high rate.  For 
        example, it was recently reported that password crackers were able to 
        try 8 billion passwords per second when passwords were hashed with the 
        MD5 algorithm. This would allow a 4 word pass phrase to be broken in 14 
        days, whereas a 6 word password would still require 4,000,000 years to 
        break.  The rate for the more computational intensive sha512 hash was 
        only 2,000 passwords per second. In this case, a 4 word pass phrase 
        would require 160,000 years to break.

        In most cases you have no control over how your passwords are stored on 
        the machines or services that you log into.  Your best defense against 
        the notoriously poor security practices of most sites is to always use 
        a unique password for sites where you are not in control of the secrets.  
        For example, you might consider using the same pass phrase for you login 
        password and the pass phrase for an ssh key on a machine that you 
        administer, but never use the same password for two different websites 
        unless you do not care if the content of those sites become public.

        So, if we return to the question of how much entropy is enough, you can 
        say that for important passwords where you are in control of the 
        password database and it is extremely unlikely to get stolen, then four 
        randomly chosen words from a reasonably large dictionary is plenty (for 
        Abraxas this is 53 bits of entropy).  If what the pass phrase is trying 
        to protect is very valuable and you do not control the password database 
        (ex., your brokerage account) you might want to follow the NIST 
        recommendation and use 6 words to get 80 bits of entropy. If you are 
        typing passwords on your work machine, many of which employ keyloggers 
        to record your every keystroke, then no amount of entropy will protect 
        you from anyone that has or gains access to the output of the keylogger.  
        In this case, you should consider things like one-time passwords or 
        two-factor authentication. Or better yet, only access sensitive accounts 
        from your home machine and not from any machine that you do not control.

        SEE ALSO
        ========
        abraxas(3), abraxas(5)
    }"""
}

# API Manpage {{{1
API_MANPAGE = {
    'name': 'abraxas',
    'sect': '3',
    'contents': r'''{
        =========
         abraxas
        =========

        ------------------------------
        collaborative password utility
        ------------------------------

        :Author: Kale and Ken Kundert <abraxas@nurdletech.com>
        :Date: {date}
        :Version: {version}
        :Manual section: 3

        .. :Copyright: Kale and Ken Kundert
        .. :Manual group: Utilities

        DESCRIPTION
        ===========
        The API to Abraxas will be simply demonstrated by example.

        archive
        +++++++

        This program is used to generate an encrypted file that includes the 
        account numbers and login information for essential accounts. The 
        resulting file could be sent to your Executor or it could be printed and 
        saved in a safe place such as a safe deposit box.  The idea is that this 
        information would help whoever needed to access your accounts in case 
        something happened to you.

        Here is the *archive* script::

            #!/bin/env python3

            from __future__ import print_function, division
            from abraxas import PasswordGenerator, PasswordError, Logging
            from textwrap import indent
            import gnupg
            import sys

            filename = 'kids.gpg'
            recipients = [
                'me@myfamily.name',
                'son@myfamily.name',
                'daughter@myfamily.name']
            accounts = [
                ('login', 'Login'),
                ('disk', 'Disk encryption'),
                ('gpg', 'GPG'),
                ('boa', 'Bank of America'),
                ('tdwaterhouse', 'TD Waterhouse')]

            try:
                logger = Logging(exception=PasswordError)
                pw = PasswordGenerator(logger=logger)
                pw.read_accounts()

                lines = []
                for name, description in accounts:
                    lines += ["%s:" % (description if description else name)]
                    acct = pw.get_account(name)

                    # Remarks
                    remarks = acct.get_field('remarks')
                    if remarks:
                        if '\n' in remarks:
                            lines += ["    remarks:"]
                            lines += [indent(remarks.strip(), '        ')]
                        else:
                            lines += ["    remarks: " + remarks.strip()]

                    # Account number
                    account = acct.get_field('account')
                    if account:
                        if type(account) == list:
                            lines += ["    account numbers:"]
                            lines += ["        %s" % ',\n        '.join(account)]
                        else:
                            lines += ["    account number:", account]

                    # Username
                    username = acct.get_field('username')
                    if username:
                        lines += ["    username:", username]

                    # Password
                    password = pw.generate_password()
                    if password:
                        lines += ["    password:", password]

                    # Security questions
                    number = 0
                    security_questions = []
                    while True:
                        try:
                            question, answer = pw.generate_answer(number)
                            security_questions += ["        %s ==> %s" % (question, answer)]
                            number += 1
                        except PasswordError:
                            break
                    if security_questions:
                        lines += ['    security questions:']
                        lines += security_questions

                    lines += []

                gpg = gnupg.GPG()
                encrypted = gpg.encrypt('\n'.join(lines), recipients)
                if not encrypted.ok:
                    sys.exit("%s: unable to encrypt.\n%s" % (filename, encrypted.stderr))
                try:
                    with open(filename, 'w') as file:
                        file.write(str(encrypted))
                    print("%s: created." % filename)
                except IOError as err:
                    sys.exit('%s: %s.' % (err.filename, err.strerror))

            except KeyboardInterrupt:
                sys.exit('Killed by user')
            except PasswordError as err:
                sys.exit(str(err))

        The program starts by creating a logger. Normally this is not necessary.  
        When you run PasswordGenerator() without passing in a logger the default 
        logger is created for you. However, the default logger does not throw 
        exceptions. Instead, when a problem occurs an error message is printed 
        to standard error and the program exits. However, this utility needs 
        exceptions to be caught and handled, and so in this case a logger is 
        explicitly created and PasswordError is passed in.  In this way, Abraxas 
        does not exit on an error, instead it throws a PasswordError.

        mountall
        ++++++++

        Here is a program that mounts a series of directories. It differs from 
        the above script in that is uses autotype, which it accesses through 
        *AutotypeWriter*. Specifically, the program never requests a password 
        directly from Abraxas. Instead, the PasswordGenerator object is passed 
        in when creating a AutotypeWriter object. It then queries the generator 
        directly for the password and then gets it directly to the user.

        Mountall uses *sudo*, which requires a password the first time it is 
        run, and it runs *mount* for each directory, which requires a password 
        each time it is run.

        Here is the *mountall* script::

            #!/bin/env python

            from __future__ import print_function, division
            from fileutils import expandPath, makePath, ShellExecute as Execute, ExecuteError
            from sys import exit
            from os import fork
            from time import sleep
            from abraxas import PasswordGenerator, AutotypeWriter, PasswordError

            shares = {{
                'music': 'audio',
                'lib/passwords': True,
                'business': True,
                'consulting': True,
                'home': True,
                'personal': True,
                'photos': True,
                'profession': True,
                'reference': True}}

            def run_cmd_with_password(cmd, pw_writer):
                try:
                    if (fork()):
                        Execute(cmd)
                    else:
                        sleep(1)
                        pw_writer.write_autotype()
                        pw_writer.process_output()
                        exit()
                except PasswordError as err:
                    exit(err.message)

            try:
                # Open the password generator
                pw = PasswordGenerator()
                pw.read_accounts()
                writer = AutotypeWriter(pw)

                # Clear out any saved sudo credentials. This is needed so that 
                # we can be sure the next run of sudo requests a password.  
                # Without this, the password that is autotyped may be exposed.
                Execute('sudo -K')

                # Get the login password
                pw.get_account('login')

                # Run sudo so that it requests the password and sets the 
                # credentials. In this way the subsequent calls to sudo will not 
                # request a password.
                run_cmd_with_password('sudo true', writer)

                # Get the Samba password
                pw.get_account('dgc21')

                for src, dest in shares.items():
                    if dest == True:
                        dest = src
                    absdest = expandPath(makePath('~', dest))
                    mountpoint = pipe('mountpoint -q %s' % absdest, accept=(0,1))
                    if mountpoint.status:
                        print("Mounting %s to %s" % (src, absdest))
                        run_cmd_with_password('sudo mount %s' % (absdest), writer)
                    else:
                        print("Skipping %s (already mounted)" % (dest))
            except KeyboardInterrupt:
                exit('Killed by user')
            except ExecuteError as err:
                exit(str(err))
            except PasswordError, err:
                sys.exit(str(err))

        The program starts by instantiating both the *PasswordGenerator* and the 
        *AutotypeWriter* class. The *PasswordGenerator* class is responsible for 
        generating the password and *AutotypeWriter* gets it to the user. In 
        this case the autotype facility is used to mimic the keyboard. There are 
        other writers available for writing to a TTY, to stdout, and to the 
        system clipboard.

        addkeys
        +++++++

        This script is used to pre-load a series of SSH keys into the SSH 
        agent. It is stimilar to the above script, except it uses pexpect 
        rather than autotype. This makes it a bit safer because pexpect waits 
        for the expected prompt from ssh-add, and so will not blindly spew out 
        the password if things go wrong::

            #!/usr/bin/python3

            import pexpect
            from abraxas import PasswordGenerator, PasswordError
            import sys

            keys = [
                # description       keyfile         abraxas account name
                ('primary rsa',     'id-rsa',       'ssh'              ),
                ('primary ed25519', 'id-ed25519',   'ssh'              ),
                ('digitalocean',    'digitalocean', 'do-ssh'           ),
                ('tunnelr',         'tunnelr',      'tunnelr-ssh'      ),
                ('dumper',          'dumper',       'dumper'           ),
                ('github',          'github',       'github-ssh'       ),
            ]
            ssh_dir = '/home/toby/.ssh'

            try:
                pw = PasswordGenerator()
                pw.read_accounts()
            except PasswordError as error:
                sys.exit(str(error))

            for desc, name, acct in keys:
                print('Adding %s ssh key' % desc)
                try:
                    acct = pw.get_account(acct)
                    password = pw.generate_password()
                    sshadd = pexpect.spawn('ssh-add %s/%s' % (ssh_dir, name))
                    sshadd.expect(
                        'Enter passphrase for %s/%s: ' % (ssh_dir, name),
                        timeout=4
                    )
                    sshadd.sendline(password)
                    sshadd.expect(pexpect.EOF)
                    sshadd.close()
                    if sshadd.exitstatus:
                        print('addkeys: ssh-add: unexpected exit status:', sshadd.exitstatus)
                except PasswordError as error:
                    sys.exit(str(error))
                except (pexpect.EOF, pexpect.TIMEOUT):
                    sys.exit('addkeys: unexpected prompt from ssh-add: %s' % (
                        sshadd.before.decode('utf8')
                    ))
                except KeyboardInterrupt:
                    exit('Killed by user')

        SEE ALSO
        ========
        abraxas(1), abraxas(5)
    }'''
}

# Configuration Files Manpage {{{1
CONFIG_MANPAGE = {
    'name': 'abraxas',
    'sect': '5',
    'contents': r'''{
        =========
         abraxas
        =========

        ------------------------------
        collaborative password utility
        ------------------------------

        :Author: Kale and Ken Kundert <abraxas@nurdletech.com>
        :Date: {date}
        :Version: {version}
        :Manual section: 5

        .. :Copyright: Kale and Ken Kundert
        .. :Manual group: Utilities

        DESCRIPTION
        ===========
        Abraxas requires two files to operate. The master password file and the 
        accounts file. You may optionally add a third file that gives the 
        dictionary used when creating pass phrases.


        Master Password File
        ++++++++++++++++++++
        The master password file is named '~/.config/abraxas/master.gpg'. It is 
        encrypted with the GPG ID that you specified when you ran 'abraxas 
        --init'.  It is a Python file that contains a collection of variables. 
        To be able to edit it conveniently it is recommended that you add the 
        gnupg plugin to vim (download it from 
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
        the hash and converting it to a password or pass phrase.  It is used to 
        warn you that the secrets code has changed, presumably when the program 
        itself was updated.  If this occurs you should verify that the passwords 
        it generates are the same. If not, you should not use the updated 
        version of the program. If they are the same, you should update the 
        *secrets_hash*. Do this by moving the existing *master.gpg* file out of 
        the way, generating a new one with *abraxas --init*, copying the new 
        *secrets_hash* to the original file, and then moving it back to its 
        original location of *~/.config/abraxas/master.gpg*.

        charsets_hash
        ~~~~~~~~~~~~~
        This is a hash of the file that contains the alphabets and the exclude 
        function that you can use when creating alphabets for your 
        character-based passwords.  It is used to warn you that the character 
        sets code has changed, presumably when the program itself was updated.  
        If this occurs you should verify that the passwords it generates are the 
        same.  If not, you should not use the updated version of the program. If 
        they are the same, you should update the *charsets_hash*. Do this by 
        moving the existing *master.gpg* file out of the way, generating a new 
        one with *abraxas --init*, copying the new *charsets_hash* to the 
        original file, and then moving it back to its original location of 
        *~/.config/abraxas/master.gpg*.

        accounts
        ~~~~~~~~
        This is the name of the accounts file. The name may be given with or 
        without an encryption suffix (``.gpg`` or ``.asc``). If given with an 
        encryption suffix, the file must be encrypted. If given without 
        a suffix, the file may still be encrypted (in which case the file itself 
        should have a encryption suffix) but need not be.

        passwords
        ~~~~~~~~~
        This is a dictionary that gives your master passwords. Each entry is 
        a pair of the password ID and then password itself. For example::

            passwords = {{
                'default': """l8i6-v?>GCTQK"oz3yzZg5Ne=&,.!*Q$2ddEaZbESwnl<4*BRi1D887XQ!W4/&}}e""",
                'derrick and peter': "hush puppie",
                'derrick and debbie': "lounge lizard",
            }}

        As shown, your account comes preloaded with a very long and very random 
        default password.

        Generally you will never have to type these passwords again, so there is 
        little reason not to make them long and very random. There are no limits 
        on the length of the passwords or the characters they may contain, so 
        you can go wild. For example, using your default master password you 
        could use Abraxas to generate new master passwords::

            $ abraxas -T =extreme 'derrick and peter'
            PASSWORD: [Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|

        You can then use that string as a master password. Notice that this 
        string contains quote characters, meaning that you will have to embed it 
        in triple quotes to avoid trouble::

            passwords = {{
                'default': """l8i6-v?>GCTQK"oz3yzZg5Ne=&,.!*Q$2ddEaZbESwnl<4*BRi1D887XQ!W4/&}}e""",
                'derrick and peter': """[Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|""",
                'derrick and debbie': "lounge lizard",
            }}

        Of course it is not necessary to go to these extremes. Your password 
        must just not be guessable. One reason not to go to such extremes is if 
        you need to share a master password with a friend while talking over the 
        phone.  In this case, using the =master template to generate a simple 
        but long pass phase is much preferred::

            $ abraxas -T =master "derrick and debbie"
            PASSWORD: impulse nostril double irony conflate rookie posting blind

        Then your passwords entry becomes::

            passwords = {{
                'default': """l8i6-v?>GCTQK"oz3yzZg5Ne=&,.!*Q$2ddEaZbESwnl<4*BRi1D887XQ!W4/&}}e""",
                'derrick and peter': """[Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|""",
                'derrick and debbie': """impulse nostril double irony conflate rookie posting blind""",
            }}

        This approach of using the default password to generate new master 
        passwords, each of which has a very predictable name, can make it 
        possible for you to reconstruct your master password file if you happen 
        to lose it. To do so, you will need to keep a copy of the default 
        password in a safe place (along with your master GPG keys in a safe 
        deposit box, for example). Of course, you really should save both 
        the master password and accounts file in a safe place because they 
        contain additional information that is used to generate your passwords 
        (account names, versions, security questions, etc.). You should be aware 
        that these tend to change with time and so your saved files can quickly 
        go out of date.  However, if your follow a practice of using very 
        systematic naming strategies for master passwords, accounts, versions, 
        and the like, you can dramatically increase the chances of being able to 
        retrieve your passwords from an old master password and accounts file.

        You are free to name your master passwords in any manner that pleases 
        you. One reasonable approach is to name them after the people that use 
        them. Thus in the example above, Derrick has one key he uses his default 
        key for for his own accounts and two others for accounts he shares with 
        Debbie and Peter. When it comes time to abandon a master password, 
        simply add '(deprecated <date>)' to the end of the master password name, 
        where <date> is replaced with the date that the password was deprecated.  
        When doing so, be sure to also change the name used in the *accounts* 
        file so that the existing passwords do not change. That way you do not 
        have to update all of your passwords at once. Rather, you update the 
        high value ones immediately and migrate the others as you get time.

        Using this approach your master password file might look like this::

            passwords = {{
                'default': """l8i6-v?>GCTQK"oz3yzZg5Ne=&,.!*Q$2ddEaZbESwnl<4*BRi1D887XQ!W4/&}}e""",
                'derrick and peter (deprecated 120301)':
                    """[Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|""",
                'derrick and peter': """h#KLT@f0IN(srTs$CBqRvMowBfiCT26q\yox(]w!PSlj_|ZMuDZ|{{P0Jo4:aa4M"""
                'derrick and debbie': """impulse nostril double irony conflate rookie posting blind""",
            }}

        Generally one uses the default password for the personal passwords, and
        only creates new shared master passwords. In this case, one member of
        the group uses their master password to generate a the shared password
        for the group. And of course, you should strive to keep your master 
        passwords completely secure. Never disclose a master password to anyone 
        else unless you plan to share that particular master password with them 
        to generate shared passwords.

        default_password
        ~~~~~~~~~~~~~~~~
        The ID of the default master password::

            default_password = "default"

        This password will be used when an account does not explicitly specify 
        a master password. It is recommended you set the default master password 
        once and after that never change it, because if you do, the passwords 
        that rely on it will also change. You are given a very secure default 
        password when your master password file is initially created for you. It 
        is recommended that you never change it.

        Using a value of None for default_password disables the default 
        password, forcing you to always specify a master password. If the master 
        password is not given in the accounts file, it will be requested when 
        Abraxas is run, which allows you to use a master password that is not 
        stored in the master password file.  This provides the ultimate in 
        security for stealth accounts in that even if someone guessed the name 
        of your stealth account and had access to your private GPG key, perhaps 
        because you were compelled to give it to them, they still could not 
        regenerate the pass phrase for your stealth account because it requires 
        a master password that only you know but can plausibly deny having.

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
        passwords generated by Abraxas.

        additional_master_password_files
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        A list of additional master password files. This is helpful in cases 
        where you want to have a separate file for passwords shared with others.  
        The additional master password files must also be encrypted.  If they 
        are truly shared, then you will want to encrypt them using multiple 
        recipients.

        An additional master password file is also a Python file, and the only 
        things that are used by Abraxas in this file are the dictionaries named 
        *passwords* and *password_overrides*.

        You can specify a single master password file using a string, and 
        multiple master password files as a list of strings.  Here is how to 
        specify a single additional master password file::

            additional_master_password_files = "business/master.gpg"

        Here is how you specify multiple additional master password files::

            additional_master_password_files = [
                "business/master.gpg",
                "charity/master.gpg"
            ]


        Accounts File
        +++++++++++++

        The accounts file is by default '~/.config/abraxas/accounts', but could 
        also end with either a '.gpg' or '.asc' extension if it is encrypted.  
        It starts out importing some character sets.  You are free to modify 
        these but there is generally no reason to.  They are there to help you 
        create alphabets for your passwords.  A function exclude() is also 
        defined, which allows you to create an alphabet by removing characters 
        from the preexisting ones.  You can add characters simply summing them.

        The accounts file is a Python file that contains variables that are used
        by the password program. When created it will lead off with some useful 
        imports. The *dedent* function is used to strip off leading white space 
        from multiline remarks. The passwords.charsets import provides 
        a collection of useful character sets::

            LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
            UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            LETTERS = LOWERCASE + UPPERCASE
            DIGITS = "0123456789"
            ALPHANUMERIC = LETTERS + DIGITS
            HEXDIGITS = "0123456789abcdef"
            PUNCTUATION = """!"#$%&'()*+,-./:;<=>?@[\]^_`{{|}}~"""
            WHITESPACE = " \t"
            PRINTABLE = ALPHANUMERIC + PUNCTUATION + WHITESPACE
            DISTINGUISHABLE = exclude(ALPHANUMERIC, 'Il1O0\\t')

        Finally, the *exclude* function is used to remove characters from 
        a character set.

        The following attributes are read and used by the password program if 
        they exist in an accounts file.

        log_file
        ~~~~~~~~

        Specifies the location of the log file. If not given, it defaults to 
        '~/.config/abraxas/log'. An absolute path should be used to
        specify the file. If a '.gpg' or '.asc' suffix is given on this file, it 
        will be encrypted using your public key. Without encryption, this file 
        leaks account names.

        archive_file
        ~~~~~~~~~~~~

        Specifies the location of the archive file. If not given, it defaults to
        '~/.config/abraxas/archive.gpg'.  An absolute path should be used to 
        specify the file. The file should end with a .gpg extension.

        gpg_id
        ~~~~~~

        The GPG ID of the user (it is used to encrypt the archive file). It 
        would either by the email address associated with the ID, or the eight 
        digit hexadecimal GPG key ID if you have multiple keys associated with 
        the same email address.

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
                "=words": {{  # typically used for Linux pass phrases
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

        In this example '=words' is specified as the template for 'gmail' (it is
        a purely optional convention to add a leading = to account names that
        are intended to be used only as templates). Thus any field specified in
        '=words' that is not specified in 'gmail' is inherited by 'gmail'. Any
        field specified in 'gmail' overrides the field with the same name from
        '=words' when using 'gmail'. This process of inheritance can chain
        through any number of templates or accounts. For example, you can create
        another account, say 'gmail-work' that uses 'gmail' as a template but
        overrides the 'username'.

        The ID associated with an account is used in the process of generating
        the secrets for the account. For this reason you should choose IDs that
        are unambiguous and unlikely to change. The resulting IDs may be long
        and hard to type. You can use the *aliases* entry to specify shorter
        names that can be used as an alternative to the primary account ID. For
        example, when creating your gmail account, it is a good idea to add your
        username to the account ID, because in the future you might create
        additional gmail accounts. So, *gmail-username* would be a good account
        name. Then you should add a short name like *gmail* as an alias to the
        one you use the most. If at some point you migrate to a new gmail
        account for your day-to-day use, you can move the *gmail* alias to this
        new account without changing the generated password.

        additional_accounts
        ~~~~~~~~~~~~~~~~~~~

        A list of additional account files. This is helpful in cases where you 
        want to have a separate file for accounts shared with someone else. In 
        this way you can share the details of the shared accounts file without 
        exposing your personal accounts. The additional account files may also 
        be encrypted.  If they are truly shared, then you will want to encrypt 
        them using multiple recipients.

        An additional accounts file is also a Python file, and the only thing
        that is used by Abraxas in this file is a dictionary named *accounts*.  
        It is generally a good idea to start from a copy of the original 
        accounts file and simply delete unnecessary definitions (*log_file*, 
        *archive_file* and *gpg_id*) and the non-shared accounts.  In this way, 
        you still can use the character sets that are defined at the top of 
        the file.

        You can specify a single account file using a string, and multiple 
        account files as a list of strings.  Here is how to specify a single 
        additional account file::

            additional_accounts = "business/accounts"

        Here is how you specify multiple additional account files::

            additional_accounts = ["business/accounts", "charity/accounts"]

        Accounts Fields
        +++++++++++++++

        Each dictionary in *accounts* may contain a number of fields that are 
        described next. When first created the accounts dictionary comes with 
        some useful templates and an example account entry that is commented 
        out. Feel free to modify the templates and delete the example account.

        template
        ~~~~~~~~
        A string containing the ID of the template for this account (explained 
        above).

        master
        ~~~~~~
        A string containing the ID of the master password for this account.
        It is recommended that each account explicitly declare its master 
        password (perhaps through a template). That way existing passwords do 
        not change if you were to change your default master password.

        version
        ~~~~~~~
        The version is a string and its contents are arbitrary, however when its 
        contents change so to does the generated password. So it can be as 
        simple as a number or it could be a date or whatever you like. But it is 
        good if you pick a convention and stick with it so that if you somehow 
        lose your accounts file you still have some hope of recovering your 
        passwords.

        Some websites put odd restrictions on the generated passwords, such as 
        it must contain a digit and a symbol or it imposes a limit on the 
        maximum number of repeated characters. Some of these restrictions can be 
        satisfied by adding a prefix or a suffix, but for others, like the 
        repeated character limit, there is no built in support in Abraxas to 
        always satisfy them. In this case you can simply bump the version until 
        you get a password that meets their requirements.

        password-type
        ~~~~~~~~~~~~~
        The type of password to generate. Should be either 'words' (default) to 
        generate pass phrases or 'chars' to generate passwords.

        num-words
        ~~~~~~~~~
        The number of words to use in the pass phrase when 'type' is 'words' 
        (default is 4).

        separator
        ~~~~~~~~~
        A string that is used as the inter-word separator when 'type' is 
        'words'. If not given, a space is used.

        num-chars
        ~~~~~~~~~
        The number of characters to use in the passwords when 'type' is 'chars' 
        (default is 12).

        alphabet
        ~~~~~~~~
        A string containing the characters to use when creating a password when 
        'type' is 'chars'. The default alphabet consists of the standard upper 
        and lower case letters along with the digits.

        prefix
        ~~~~~~
        A string whose contents are added to the beginning of a password or 
        passphrase.

        suffix
        ~~~~~~
        A string whose contents are added to the end of a password or 
        passphrase.

        aliases
        ~~~~~~~
        List of names that can be used as aliases for this account.  This 
        feature is often used to specify a shorter and easier to type name for 
        the account. 

        The secrets are generated based on the primary account name (the key for
        dictionary that describes the account). As such, that name should be
        chosen so that it is unambiguous and you will never be tempted to change
        it.  That often results in a name that is too long to type easily.  This
        entry allows you to specify one or more names that can be used as
        aliases for the primary account name.  For example, you might want to
        choose a name like "gmail-derrickAsh" as the primary name of your gmail
        account and "gmail" as an alias. This would allow you to later create
        another gmail account and make it your primary gmail account simply by
        moving the "gmail" alias the new account.

        When sharing your accounts you may not wish to share your aliases. For 
        example, if both you and your partner have accounts at Chase you may 
        want to both use the alias Chase to refer to two different accounts.  
        You can arrange this by using some Python code as follows::

            from getpass import getuser

            accounts = {{
                'chase-amy': {{
                    'aliases': ['chase'] if getuser() == 'amy' else []
                    ...
                }},
                'chase-laura': {{
                    'aliases': ['chase'] if getuser() == 'laura' else []
                    ...
                }},
            }}

        username
        ~~~~~~~~
        A string containing the username for the account.

        account
        ~~~~~~~
        Either an account identifier for the account or a list containing 
        multiple account identifier. Account identifiers must be given as 
        strings.

        email
        ~~~~~
        A string containing the email address associated with the account.

        url
        ~~~
        A string containing the web address of the account or a list of strings 
        each containing a web address.

        If a list of URLs are provided, the first will be used with the 
        ``--browser`` and ``--default-browser`` command line arguments. In this 
        case, the browser will be started and directed to display the first 
        address. All the addresses are used in account discovery. If a URL 
        component is discovered in a title bar, it will be compared against all 
        of the URLs given in the list looking for a match. The URLs may be glob 
        strings to generalize the matching. Given that the first URL can be sent 
        to the browser it is best not to use globbing in the first URL.

        When a URL is used in account discovery, the presence of the 
        communication protocol is significant. If the URL starts with 
        'https://', then Abraxas insists on the use of an encrypted link.  
        If the link is not encrypted, the account will not be selected as 
        a match and a warning will be issued (this is a relatively common way of 
        tricking you into disclosing your password). Even if the URL 
        does not start with 'https://', Abraxas will also require 
        a encrypted link if PREFER_HTTPS is set to True in ``password/prefs.py`` 
        unless the URL starts with 'http://'.

        remarks
        ~~~~~~~
        A string containing any relevant remarks about the account. You can 
        create a multiline remark as follows::

            'remarks': dedent("""
                Wireless network settings:
                    SSID: ourhouse
                    Network security: WPA2 Personal
            """)

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
        then get the answers by running Abraxas, and then copying the 
        answers into the web page for your account. In this way, your answers 
        will be quite unpredictable, even to those that know you well.

        The answers to the security questions will change if you change your 
        security questions. Even the smallest change will result in a completely 
        different answer. Once you have given the answers to your account 
        provider you must not change the question at all unless you are willing 
        to go through the trouble of updating the answers.

        window
        ~~~~~~
        This may be either a glob string or a list of glob strings that match 
        the title of the web page used to enter the username/password for the 
        account. This is used to determine which account should be used if no 
        account name is given on the command line.

        This enables you to set up a hot key, such as Alt-P, to run 'abraxas
        --autotype', which will identify which account to use from the active 
        window title and then use the *autotype* field to log you in.

        When using commands from a shell the title of the window is generally 
        unaffected by the command that is running. However, you can write 
        a simple script that first sets the window title and then runs the 
        command. Here is an example of such a script for mutt::

            #!/bin/sh
            xdotool getactivewindow set_window --name "Mutt"
            mutt

        Alternatively, you can switch to Lilyterm, which is a Linux terminal 
        emulator that I can recommend and that plays particularly nicely with 
        Abraxas. It copies the command being run to the window title so it 
        can be used to determine which account to use.

        Generally the window feature works well with web browsers, though some 
        sites neglect to put identifying information in the title bar of their 
        login page.  This can be addressed in Firefox and Thunderbird by 
        installing the 'Hostname in Titlebar' add on. In Chrome, use 'Url in 
        Title'. They add the URL to the title bar, making it available to be 
        matched with a window glob string.  This add on also adds the protocol 
        to the title as well. That allows you to key the password in such a way 
        that it will not autotype unless the connection is encrypted (the 
        protocol is https).

        In its default configuration, Abraxas recognizes the components 
        in a 'Hostname in Titlebar' title. Those components, which include the 
        title, the hostname, and the communication protocol (http or https), and 
        compare those to the corresponding entries in each account. The title is 
        compared to the *window* entries and the hostname and protocol are 
        compared against the *url*.  If no match is made with these components, 
        then the raw title is compared against the *window* entries.

        When sharing your accounts with a partner you may not wish to share your 
        window settings.  For example, if both you and your partner have 
        accounts at Chase and you both want to have the window title on the 
        Chase web page to trigger your own account. You can arrange this by using 
        some Python code as follows::

            from getpass import getuser

            accounts = {{
                'chase-amy': {{
                    'window': ['CHASE Bank*'] if getuser() == 'amy' else []
                }},
                'chase-laura': {{
                    'window': ['CHASE Bank*'] if getuser() == 'laura' else []
                }},
            }}

        You might also find that you need different passwords on different 
        machines. For example, you may have root access on several machines, 
        each of which has a different root password. You can handle this as 
        follows::

            from socket import gethostname
            accounts = {{
                'root-mars': {{
                    'template': '=words',
                    'window': ['su'] if gethostname() == 'mars' else []
                }},
                'root-venus': {{
                    'template': '=words',
                    'window': ['su'] if gethostname() == 'venus' else []
                }},
            }}

        autotype
        ~~~~~~~~
        A string containing a script that controls autotyping (when the -t or 
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

        Other Fields
        ~~~~~~~~~~~~
        The value of all other fields will be printed when the user requests all 
        information about the account.

        Words File
        ++++++++++
        The words file is '~/.config/abraxas/words'. The use of this file is 
        optional.  Abraxas has its own words that it uses if you do not provide 
        a file yourself. It should contain a large number of words (thousands), 
        one word per line. The more words your file contains, the more secure 
        your pass phrases are, however anymore than 65,536 are not used.

        Do not change this file once you have started creating passwords, and be 
        sure to back it up. Any change to this file will cause the generated 
        pass phrases to change, which means you will not be able to use 
        Abraxas to login to existing accounts that use pass phrases.

        EXAMPLE
        =======

        Master Password File
        ++++++++++++++++++++

        Here is a representative master password file 
        (~/.config/abraxas/master.gpg)::

            dict_hash = "d9aa1c08e08d6cacdf82819eeb5832429eadb95a"
            secrets_hash = "db7ce3fc4a9392187d0a8df7c80b0cdfd7b1bc22"
            passwords = {{
                'derrick and peter': "e9a7a4246a6a95f179cd4579e6f9cb69",
                'derrick and debbie': "60b56e021118ca2a261f405e15ac0165",
                'default': """[Y$*{{QCf"?yvDc'{{4v?4r.iA0b3brHY z40;lZIs~bjj<DpDz&wK!XCWq=,gb}}-|""",
            }}
            default_password = 'default'
            password_overrides = {{
                'yahoo': 'lollipop',
                'nytimes': 'excelsior',
            }}


        Accounts File
        +++++++++++++

        Here is a representative accounts file (~/.config/abraxas/accounts) with 
        the boilerplate code generated by Abraxas itself stripped off for 
        brevity::

            # Give the desired location of the file
            logfile = '~/.config/abraxas/log'

            # Account Information
            accounts = {{
                # Templates
                "=words": {{  # typically used for Linux pass phrases
                    'type': 'words',
                    'num-words': 4,
                    'autotype': "{{password}}{{return}}",
                }},
                "=chars": {{  # typically used for web passwords
                    'type': 'chars',
                    'num-chars': 12,
                    'alphabet': ALPHANUMERIC + PUNCTUATION,
                    'autotype': "{{username}}{{tab}}{{password}}{{return}}",
                }},

                # Accounts
                "login": {{
                    'template': "=words",
                    'window': [
                        'su',
                        'su *',
                    ]
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
                    'url': "https://hpcu.com",
                    'account': "1987-357836",
                    'window': [
                        'HP Credit Union*',
                        'Hewlett-Packard Credit Union*',
                    ],
                    'autotype': "{{account}}{{tab}}{{password}}{{return}}",
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
                    'template': "=chars",
                    'username': "derrickAsh",
                    'email': "derrickAsh@gmail.com",
                    'url': "https://login.yahoo.com",
                    'window': 'Sign into Yahoo!*',
                }},
                "nytimes": {{
                    'template': "=chars",
                    'username': "derrickAsh",
                    'email': "derrickAsh@gmail.com",
                    'url': "https://myaccount.nytimes.com/auth/login",
                    'window': '*The New York Times*',
                }},
                "consumer-reports": {{
                    'template': "=chars",
                    'master': 'derrick and debbie',
                    'username': "DandD",
                    'url': "https://ec.consumerreports.org/ec/myaccount/login.htm",
                    'window': 'My account login*',
                }},
            }}

        CONFIGURATION
        =============
        The file ``passwords/prefs.py`` in the source code contains various 
        configuration settings that can be set to change the behavior of 
        Abraxas. You should be careful when changing these. Some settings 
        can be changed with little concern, but others match the implementation 
        and changing them my require changes to the underlying code.

        SEE ALSO
        ========
        abraxas(1), abraxas(3)
    }'''
}

# Generate restructured text {{{1
def write(genRST=False):
    for each in [PROGRAM_MANPAGE, API_MANPAGE, CONFIG_MANPAGE]:
        rst = dedent(each['contents'][1:-1]).format(
            date=DATE,
            version=VERSION,
            search_fields=', '.join(SEARCH_FIELDS)
        )

        # generate reStructuredText file (only used for debugging)
        if genRST:
            print("generating %s.%s.rst" % (each['name'], each['sect']))
            with open('%s.%s.rst' % (each['name'], each['sect']), 'w') as f:
                f.write(rst)

        # Generate man page
        print("generating %s.%s" % (each['name'], each['sect']))
        with open('%s.%s' % (each['name'], each['sect']), 'w') as f:
            f.write(publish_string(rst, writer=manpage.Writer()).decode())

if __name__ == '__main__':
    write(True)

# vim: set sw=4 sts=4 formatoptions=ntcqwa12 et spell:
