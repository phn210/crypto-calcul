#!/bin/sh

set -x

rm -rf .venv

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

make wrap_fast