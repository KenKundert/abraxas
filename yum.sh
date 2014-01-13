#!/usr/bin/env sh

sudo yum install            \
    python                  \
    python-setuptools       \
    libyaml-devel           \
    python-docutils         \
    PyYAML                  \
    xdotool                 \
    xsel                    \
    zenity

sudo easy_install python-gnupg
