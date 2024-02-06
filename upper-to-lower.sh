#!/usr/bin/env zsh

# necessita do zsh
# .zshrc: autoload zmv
zmv -o -i '(**/)(*)' '$1${2:1}'
