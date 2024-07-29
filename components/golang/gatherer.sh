#!/bin/bash

. ./scripts/get_freq.sh

CURVE="NIST256p"
COMPONENT="golang"
SAMPLES=1000000
RESULTS_DIR="/minerva-results"
GATHERER="time_sign_golang.go"
CPU=""

_EXTRA_EXTRACT_FLAGS="--prehashed "
_PYTHONBIN="./minerva-venv/bin/python"

if ! [[ -x `which go` ]]; then
    echo "Error: Golang command line utility is necessary for this script" >&2
    exit 1
fi

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
echo "                          Default NIST256p"
echo "-s, --samples num     Number of samples per run per core."
echo "                          Default 1000000"
echo "--dir dir             Custom dir to use for the results."
echo "                          Default /minerva-results"
echo "--gatherer path       Use a custom gatherer."
echo "                          Default time_sign_openssl.c"
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

mkdir -p $RESULTS_DIR

GOLANG_VERSION=$(go version)
echo "Tesing Golang version $GOLANG_VERSION"

echo "[i] Getting frequency of the machine..."
TSC_FREQUENCY="$(get_freq)"
echo "[i] Detected freq: $TSC_FREQUENCY MHz"

_TASKSET_CMD=""
if ! [[ -z "$CPU" ]]; then
    _TASKSET_CMD="taskset --cpu-list $CPU"
fi

$_TASKSET_CMD $_PYTHONBIN scripts/collect.py -v -o $RESULTS_DIR -c $CURVE \
    -n $SAMPLES --gather $GATHERER --component $COMPONENT

if [[ $? == 0 ]]; then
    PYTHONPATH=tlsfuzzer $_PYTHONBIN tlsfuzzer/tlsfuzzer/extract.py -o $RESULTS_DIR \
        --raw-times $RESULTS_DIR/times --binary 8 --raw-data $RESULTS_DIR/data \
        --data-size 32 --raw-sigs $RESULTS_DIR/sigs --verbose \
        --priv-key-ecdsa $RESULTS_DIR/priv_key.pem --clock-frequency $TSC_FREQUENCY \
        $_EXTRA_EXTRACT_FLAGS
fi