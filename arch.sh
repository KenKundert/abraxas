#!/usr/bin/env sh
# Run this script as yourself on an Arch Linux system to get needed 
# dependencies.

pacman -S git
pacman -S python
pacman -S python-setuptools
pacman -S python-docutils
pacman -S libyaml
pacman -S xdotool
pacman -S xsel
pacman -S zenity
easy_install python-gnupg
easy_install PyYAML

# Other things you may need:
# pacman -S vim
# pacman -S keychain (if you prefer keychain)
# pacman -S gnome-keyring (if you prefer keyring)
