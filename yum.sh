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
