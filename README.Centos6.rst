Installing on Centos6.2
=======================

Installing Prerequisites
------------------------

Installing Abraxas on any machine can be a bit of a challenge, mainly because of 
GPG, which can take some work to get set up properly. However, getting GPG set 
up pays off in many ways. Besides using it for passwords, you can encrypt your 
files and your email, and you can use it to prove your identity to others. There 
is a great deal of information about this on the web if you care to search 
around a bit.

To show you how overcome many of the problems that occur when installing Abraxas 
and GPG, I will take you through the process of installing Abraxas on Centos6.2.

By default Centos comes with a rather thin set of yum repositories, and many of 
the dependencies that we will need to install are not contained in the base 
repositories. You can find the needed repositories by searching for the desired 
packages on pkgs.org.  When I did the search, I came with with the following. As 
root, run::

   # wget http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
   # rpm -Uvh epel-release-6-8.noarch.rpm

   # wget http://li.nux.ro/download/nux/dextop/el6/x86_64/nux-dextop-release-0-2.el6.nux.noarch.rpm
   # rpm -Uvh nux-dextop-release-0-2.el6.nux.noarch.rpm

   # yum install xdotool xsel libyaml zenity

Update python and install any python dependencies. As root::

   # yum install python python-setuptools

Install python-gnupg. This is where the first trouble may come. For me, running 
the command 'easy_install python-gnupg' terminated in an error. To overcome this 
I manually downloaded and installed python-gnupg::

   # wget --no-check-certificate https://pypi.python.org/packages/source/p/python-gnupg/python-gnupg-0.3.4.tar.gz
   # tar xzf python-gnupg-0.3.4.tar.gz
   # cd python-gnupg-0.3.4
   # python setup.py install

Install argparse and docutils::

   # easy_install argparse
   # easy_install docutils

Install PyYAML. Again, running the command 'easy_install PyYAML' terminated in 
an error. To overcome this I manually downloaded and installed PyYAML::
   # wget --no-check-certificate https://pypi.python.org/packages/source/P/PyYAML/PyYAML-3.10.zip
   # unzip PyYAML-3.10.zip
   # cd PyYAML-3.10
   # python setup.py install

Configuring GPG
---------------

Now you will need to configure GPG and GPG Agent. If you don't have a GPG key, 
you can create one. As you (a normal user, not root) run::

   $ gpg --gen-key
   Please select what kind of key you want:
      (1) RSA and RSA (default)
      (2) DSA and Elgamal
      (3) DSA (sign only)
      (4) RSA (sign only)
   Your selection? 1
   What keysize do you want? (2048) 4096
   Please specify how long the key should be valid.
   Key is valid for? (0) 0
   Real name: ... your name ...
   Email address: ... your email address ...
   Comment: ...
   Enter passphrase: ...

Add the following lines to your ~/.gnupg/gpg.conf file::

   use-agent
   personal-digest-preferences SHA256
   cert-digest-algo SHA256
   default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed

Normally we would use Gnome Keyring as the key agent for GPG, but the version of 
keyring available in Centos6 does not provide this feature, so we will need to 
use gpg-agent.  Create the ~/.gnupg/gpg-agent.conf file and add the following 
lines::

   default-cache-ttl 360000
   default-cache-ttl-ssh 360000
   max-cache-ttl 648000
   max-cache-ttl-ssh 648000
   log-file /home/<you>/.gnupg/gpg-agent.log

Replace ``<you>`` with your login name. The 'ttl' entries are optional, they 
just specify how long you can use the pass phrase before it expires.

You will need to have Gnome start GPG Agent (otherwise it will not work properly 
with autotype). To do so, go to 'System->Preference->Startup Applications', 
click 'Add' and add the following::

   Name: GPG Agent
   Command: eval $(gpg-agent --daemon)

While you are at it, configure Gnome to run Abraxas when you type a special key 
sequence. This will allow you to login to webpages and such just by typing the 
key sequence. To do so, go to 'System->Preference->Keyboard Shortcuts', click 
'Add' and add the following::

   Name: Password
   Command: /home/<you>/.local/bin/abraxas --autotype

Then click on the word 'Disabled' in the Shortcut column. It should switch to 
"New Shortcut ...". Then simply type your desired key sequence. I use Alt-N 
because it is easy to type, but you might prefer Alt-P for its pneumonic value.  
Now, log out and log back in.

You can now test GPG with::

   $ date > date
   $ gpg --sign date

It should ask you for you passphrase and then create the file 'date.gpg'. You 
can test to the signature with::

   $ gpg --verify date.gpg

Finally, you should delete 'date.gpg' and create the signature again::

   $ date > date
   $ gpg --sign date

This time, you should not be asked for your passphrase. If you are your 
connection to gpg-agent is broken. Look in ~/gnupg/gpg-agent.log for clues as to 
what is going wrong.

Installing Abraxas
------------------

At this point you should be able to test and install Abraxas. As you (a normal 
user, not root)::

   $ cd abraxas
   $ ./test
   abraxas: generated_settings/master.gpg: created.
   generated_settings/accounts: created.
   generated_settings/master.gpg: created.
   generated_settings/accounts: created.
   generated_settings/master.gpg: created.
   generated_settings/accounts: created.
   Warning: account 'test' not found.
   Warning: account 'fuzzbucket' not found.
   Warning: account 'none' not found.
   PASS: 60 tests run, 0 failures detected.

   $ ./install

Make sure you can access the man pages::

   $ man abraxas
   $ man 3 abraxas
   $ man 5 abraxas

Now, create your Password files using::

   $ abraxas -I <your email address>

You can give give the 8-digit hexadecimal key ID in lieu of your email address 
if you like, and that is preferred if you have multiple GPG accounts with the 
same email address. You can now test your setup using::

   $ abraxas foo
   $ abraxas -c foo
   $ abraxas -t foo

In each case it will warn you that account 'foo' cannot be found.

As your first account, you should configure Abraxas to generate your gpg 
passphrase.  Add something like the following to 'accounts' in 
~/.config/accounts::

   "gpg-BABEBEEF": {
      'aliases': ["gpg"],
      'master': "default",
      'template': "=words",
   }

where you should use your key ID rather than BABEBEEF. Now generate your new GPG 
passphrase with::

   abraxas gpg

Finally, you need to update your GPG key to use this new passphrase. To do so, 
use::

   $ gpg --edit-key <your email address>
   password

Now, in another window, run::

   abraxas -c gpg

which copies your passphrase into the clipboard temporarily, and paste this new 
passphrase into the GPG "Enter Passphrase" form. When first assigning your 
passphrase you should type it the first time and paste it the second. That way 
you do not accidentally set it to a bogus value.

Finally, you will want to test the autotype feature. To do so, edit 
~/.config/abraxas/accounts and add an web account. Be sure to add the 'window' 
and perhaps 'autotype' fields (run 'man 5 abraxas' for more information on how 
to add your account). Then visit that webpage, click on the username field, and 
type your key sequence (Alt-P?). The username and password should appear and 
then you should be logged in. If this does not happen, take a look at 
~/.config/abraxas/log for clues as to what is going wrong (you can set DEBUG to 
True in abraxas/prefs.py and reinstall for more information).  If instead of 
logging in there is a burst of extremely strange behavior, such as your windows 
being moved about the screen, you might consider editing the file 
abraxas/prefs.py and increasing the value of INITIAL_AUTOTYPE_DELAY and 
reinstalling.  If this delay is not long enough the username and password can 
confuse the window manager and be treated as a window manager command.

-Ken
