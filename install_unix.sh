#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
python3 -m pip install --user -r requirements.txt
printf "Installation complete. Try: python3 safe_url.py --help\n"
