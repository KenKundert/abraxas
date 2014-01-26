#!/usr/bin/env sh
# Run this script as yourself on an Ubuntu system to get needed dependencies.

apt-get install git
apt-get install libyaml-dev
apt-get install python3
apt-get install python3-setuptools
apt-get install python3-docutils
apt-get install python3-gi
apt-get install python3-yaml
apt-get install xdotool
apt-get install xsel
easy_install3 python-gnupg

# Other things you may need:
# apt-get install vim
# apt-get install gnupg-agent (if you prefer gpg-agent or keychain)
# apt-get install keychain (if you prefer keychain)
# apt-get install pinentry-curses (if you prefer gpg-agent or keychain without X11)
# apt-get install gnome-keyring (if you prefer keyring)
