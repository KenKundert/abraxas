#!/usr/bin/env sh
# Run this script as yourself on a Redhat system (Redhat, Fedora, CentOS) to get 
# needed dependencies.

sudo yum install       \
    python             \
    python-setuptools  \
    python-docutils    \
    pygobject3         \
    python-argparse    \
    pinentry-gtk       \
    libyaml-devel      \
    PyYAML             \
    xdotool            \
    xsel

sudo easy_install python-gnupg

# Other things you may need:
# yum install git
# yum install vim-enhanced vim-X11
# yum install keychain (if you prefer keychain)
# yum install gnome-keyring gnome-keyring-pam (if you prefer keyring)
