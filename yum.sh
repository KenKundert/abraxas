#!/usr/bin/env sh
# Run this script as yourself on a Redhat system (Redhat, Fedora, CentOS) to get 
# needed dependencies.

# Select which version of python you would like to install, choose either python 
# for python2 or python3 for python3.
python=python

sudo yum install            \
    $python                 \
    $python-setuptools      \
    libyaml-devel           \
    $python-docutils        \
    PyYAML                  \
    xdotool                 \
    xsel                    \
    zenity

sudo easy_install python-gnupg
