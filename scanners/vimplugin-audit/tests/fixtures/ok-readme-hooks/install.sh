#!/bin/sh
set -e
ver=1.0.0
curl -fsSL -o bin/ok.tar.gz "https://github.com/ok-owner/ok.vim/releases/download/v$ver/ok-$(uname -s).tar.gz"
tar -xzf bin/ok.tar.gz -C bin
