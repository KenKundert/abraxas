#!/usr/bin/env sh
# Run this script as yourself on a Redhat system (Redhat, Fedora, CentOS) to get 
# needed dependencies.

sudo yum install       \
    python             \
    python-setuptools  \
    libyaml-devel      \
    python-docutils    \
    PyYAML             \
    xdotool            \
    xsel               \
    zenity

sudo easy_install python-gnupg

# Other things you may need:
# yum install vim-enhanced vim-X11
# yum install keychain (if you prefer keychain)
# yum install gnome-keyring gnome-keyring-pam (if you prefer keyring)
