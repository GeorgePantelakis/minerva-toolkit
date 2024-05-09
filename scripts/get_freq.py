import os
import sys
import re
import math

def default_and_exit():
    print("TSC_FREQUENCY=1")
    exit(0)

def main():
    if len(sys.argv) < 2:
        default_and_exit()

    try:
        with open(os.path.join(sys.argv[1], 'processor-info'), 'r', encoding='utf-8') as in_fp:
            info = in_fp.read().splitlines()
    except FileNotFoundError:
        default_and_exit()

    refined_freqs = []
    unrefined_freqs_tsc = []
    unrefined_freqs_proc = []

    for line in info:
        if "Refined TSC clocksource calibration" in line:
            freq = float(re.findall(r'\d+\.\d+', line)[0])
            refined_freqs.append(freq)
        elif "MHz TSC" in line:
            freq = float(re.findall(r'\d+\.\d+', line)[0])
            unrefined_freqs_tsc.append(freq)
        elif "MHz processor" in line:
            freq = float(re.findall(r'\d+\.\d+', line)[0])
            unrefined_freqs_tsc.append(freq)

    average_freq = 0

    if refined_freqs:
        freqs = refined_freqs
    elif unrefined_freqs_tsc:
        freqs = unrefined_freqs_tsc
    elif unrefined_freqs_proc:
        freqs = unrefined_freqs_proc
    else:
        default_and_exit()

    total = 0
    for freq in freqs:
        total += freq * 1e6
    average_freq = math.ceil(total / len(freqs))
    average_freq /= 1e6
    print("TSC_FREQUENCY={0}".format(average_freq))
    return 0

if __name__ == '__main__':
    main()