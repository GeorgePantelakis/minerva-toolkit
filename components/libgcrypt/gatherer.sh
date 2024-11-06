#!/bin/bash

. ./scripts/get_freq.sh

CURVE="NIST256p"
COMPONENT="libgcrypt"
SAMPLES=1000000
RESULTS_DIR="/minerva-results"
STATIC=false
GATHERER="components/libgcrypt/time_sign_libgcrypt.c"
CPU=""

_EXTRA_EXTRACT_FLAGS=""
_PYTHONBIN="./minerva-venv/bin/python"

if ! [[ -d "minerva-venv" ]]; then
    echo "Error: Please first run system_prepare.sh" >&2
    exit 1
fi

while [ "$1" != "" ]; do
    case $1 in
    -h|--help)
echo "options:"
echo "-c, --curve str       Curve to be tested. Choose from NIST256p,"
echo "                      NIST384p or NIST521p."
echo "                          Default $CURVE"
echo "-s, --samples num     Number of samples per run per core."
echo "                          Default $SAMPLES"
echo "--dir dir             Custom dir to use for the results."
echo "                          Default $RESULTS_DIR"
echo "--gatherer path       Use a custom gatherer."
echo "                          Default $GATHERER"
echo "--static              Building and running libgcrypt from upstream code."
echo "--cpu cpu_num         Bind gathering script to specific CPU(s). This"
echo "                      list will be passed to taskset command."
echo "--help                Prints this message."
echo
        exit 0
        ;;
    -c|--curve)
        shift
        if [[ $# -gt 0 && $1 != -* ]]; then
            CURVE="$1"
        else
            echo "No curve provided"
            exit 1
        fi
        shift
        ;;
    -s|--samples)
        shift
        if [[ $# -gt 0 && $1 != -* ]]; then
            SAMPLES=$1
        else
            echo "No sample size provided"
            exit 1
        fi
        shift
        ;;
    --dir)
        shift
        if [[ $# -gt 0 && $1 != -* ]]; then
            RESULTS_DIR="$1"
        else
            echo "No custom directory provided"
            exit 1
        fi
        shift
        ;;
    --gatherer)
        shift
        if [[ $# -gt 0 && $1 != -* ]]; then
            GATHERER="$1"
        else
            echo "No custom gatherer provided"
            exit 1
        fi
        shift
        ;;
    --static)
        STATIC=true
        shift
        ;;
    --cpu)
        shift
        if [[ $# -gt 0 && $1 != -* ]]; then
            CPU="$1"
        else
            echo "No custom CPU number provided"
            exit 1
        fi
        shift
        ;;
    *)
        echo "Not known flag $1"
        echo "Please try --help to see all the options"
        exit 1
        ;;
    esac
done

if [[ -d $RESULTS_DIR ]]; then
    rm -rf $RESULTS_DIR/*
else
    mkdir -p $RESULTS_DIR
fi

if [[ $STATIC == true ]]; then
    if ! [[ -d "libgcrypt-code" ]]; then
        mkdir libgcrypt-code
        cd libgcrypt-code

        git clone --depth 1 https://github.com/gpg/libgcrypt.git
        git clone --depth 1 https://github.com/gpg/libgpg-error.git

        pushd libgpg-error
        ./autogen.sh
        ./configure --prefix=/usr/local --enable-maintainer-mode --enable-static
        make -j$(nproc --all || echo '1') &> $RESULTS_DIR/libgpg_error_make.log
        if [ $? -ne 0 ]; then
            echo "Couldn't build libgpg-error. See make logs in $RESULTS_DIR/libgpg_error_make.log"
            exit 1
        fi
        make install
        popd

        pushd libgcrypt
        autoreconf --install --force
        autoconf
        ./configure --enable-maintainer-mode --enable-static
        make -j$(nproc --all || echo '1') &> $RESULTS_DIR/libgcrypt_make.log
        if [ $? -ne 0 ]; then
            echo "Couldn't build libgcrypt. See make logs in $RESULTS_DIR/libgcrypt_make.log"
            exit 1
        fi
        popd

        cd ..
    fi
fi

echo "[i] Getting frequency of the machine..."
TSC_FREQUENCY="$(get_freq)"
echo "[i] Detected freq: $TSC_FREQUENCY MHz"

_TASKSET_CMD=""
if ! [[ -z "$CPU" ]]; then
    _TASKSET_CMD="taskset --cpu-list $CPU"
fi

if [[ $STATIC == true ]]; then
    $_TASKSET_CMD $_PYTHONBIN scripts/collect.py -v -o $RESULTS_DIR -c $CURVE \
        -n $SAMPLES --gather $GATHERER --component $COMPONENT --keep-flags \
        --gcc-flags "-Lopenssl/ -Iopenssl/include/"
else
    $_TASKSET_CMD $_PYTHONBIN scripts/collect.py -v -o $RESULTS_DIR -c $CURVE \
        -n $SAMPLES --gather $GATHERER --component $COMPONENT
fi

if [[ $? == 0 ]]; then
    PYTHONPATH=tlsfuzzer $_PYTHONBIN tlsfuzzer/tlsfuzzer/extract.py -o $RESULTS_DIR \
        --raw-times $RESULTS_DIR/times --binary 8 --raw-data $RESULTS_DIR/data \
        --data-size 32 --raw-sigs $RESULTS_DIR/sigs --verbose \
        --priv-key-ecdsa $RESULTS_DIR/priv_key.pem --clock-frequency $TSC_FREQUENCY \
        --prehashed --sig-format RAW $_EXTRA_EXTRACT_FLAGS
fi

rm -rf openssl