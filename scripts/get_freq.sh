#!/bin/bash

function get_freq() {
    local TSC_FREQUENCY=""

    if [[ "$(uname -m)" == "x86_64" ]]; then
        _TSC_INFO="$(cat /var/log/messages | grep -i -o 'tsc:.*')"
        if [ -z "$_TSC_INFO" ]; then
            _TSC_INFO="$(cat /var/log/anaconda/journal.log | grep -i -o 'tsc:.*')"
        fi
        if [ -z "$_TSC_INFO" ]; then
            _TSC_INFO="$(dmesg | grep -i -o 'tsc:.*')"
        fi
        echo \"$_TSC_INFO\" > $RESULTS_DIR/processor-info
        $_PYTHONBIN scripts/get_freq.py $RESULTS_DIR > /tmp/freq
        . /tmp/freq
        rm -f /tmp/freq
    elif [[ "$(uname -m)" == "s390x" ]]; then
        TSC_FREQUENCY=4096
        _EXTRA_EXTRACT_FLAGS+="--endian big "
    else
        gcc scripts/get_freq.c -o get_freq
        ./get_freq > /tmp/freq
        . /tmp/freq
        rm -f get_freq /tmp/freq
    fi

    echo $TSC_FREQUENCY
}