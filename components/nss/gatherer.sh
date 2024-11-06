#!/bin/bash

. ./scripts/get_freq.sh

CURVE="NIST256p"
COMPONENT="nss"
SAMPLES=1000000
RESULTS_DIR="/minerva-results"
STATIC=false
GATHERER="components/nss/time_sign_nss.c"
CPU=""

_COLLECT_VARS=""
_EXTRA_COLLECT_FLAGS=""
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
echo "--static              Building and running NSS from upstream code."
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
    if ! [[ -d "nss-build" ]]; then
        if ! [[ -x `which hg` ]]; then
            echo "Error: Mercury command line utility (hg) is necessary for this script" >&2
            exit 1
        fi

        PREFIX="nss-build/dist/Debug"
        _COLLECT_VARS+="LD_LIBRARY_PATH=$PREFIX/lib/ "
        _EXTRA_COLLECT_FLAGS+="--gcc-flags \"-static -Inss-build/dist/public/nss/ -I$PREFIX/include/nspr/ -L$PREFIX/lib/ -lpk11wrap_static -lnss_static -lpk11wrap_static -lnsspki -lnssb -lnssdev -lsoftokn_static -lfreebl_static -lhw-acc-crypto-avx2 -lhw-acc-crypto-avx -lgcm-aes-x86_c_lib -lsha-x86_c_lib -lsqlite -lcryptohi -lcertdb -lnssutil -lcerthi -lplds4 -lplc4 -lnspr4\""

        $_PYTHONBIN -m pip install gyp-next
        mkdir nss-build && cd nss-build
        hg clone https://hg.mozilla.org/projects/nspr
        hg clone https://hg.mozilla.org/projects/nss

        rlRun "pushd nss"

        rlRun "./build.sh --static &> $RESULTS_DIR/nss_build.log"
        if [ $? -ne 0 ]; then
            echo "Couldn't build NSS. See make logs in $RESULTS_DIR/nss_build.log"
            exit 1
        fi
        rlRun "popd"
        rlRun
    fi
fi

echo "[i] Getting frequency of the machine..."
TSC_FREQUENCY="$(get_freq)"
echo "[i] Detected freq: $TSC_FREQUENCY MHz"

_TASKSET_CMD=""
if ! [[ -z "$CPU" ]]; then
    _TASKSET_CMD="taskset --cpu-list $CPU"
fi

$_COLLECT_VARS $_TASKSET_CMD $_PYTHONBIN scripts/collect.py -v -o $RESULTS_DIR \
    -c $CURVE -n $SAMPLES --gather $GATHERER --component $COMPONENT \
    $_EXTRA_COLLECT_FLAGS

if [[ $? == 0 ]]; then
    PYTHONPATH=tlsfuzzer $_PYTHONBIN tlsfuzzer/tlsfuzzer/extract.py -o $RESULTS_DIR \
        --raw-times $RESULTS_DIR/times --binary 8 --raw-data $RESULTS_DIR/data \
        --data-size 32 --raw-sigs $RESULTS_DIR/sigs --verbose \
        --priv-key-ecdsa $RESULTS_DIR/priv_key.pem --clock-frequency $TSC_FREQUENCY \
        $_EXTRA_EXTRACT_FLAGS
fi

rm -rf nss-build