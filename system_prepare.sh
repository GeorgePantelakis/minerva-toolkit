#!/bin/bash

PYTHONBIN=`which python3`

if ! [[ -x `which git` ]]; then
    echo "Error: Git is necessary to execute the script" >&2
    exit 1
fi

if ! [[ -x $PYTHONBIN ]]; then
    echo "Error: Python command line utility is necessary for this script" >&2
    exit 1
fi

if ! [[ -d minerva-venv ]]; then
    $PYTHONBIN -m venv minerva-venv
fi

if ! [[ -d tlsfuzzer ]]; then
    git clone --depth=1 https://github.com/tlsfuzzer/tlsfuzzer.git
else
    echo "Info: tlsfuzzer detected, not upgrading"
fi

pushd tlsfuzzer
../minerva-venv/bin/pip install -r requirements.txt -r requirements-timing.txt
popd

chmod +x ./components/*/*.sh ./scripts/get_freq.sh