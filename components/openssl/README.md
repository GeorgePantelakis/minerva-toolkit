Test scripts for OpenSSL implementation.

## Required

The following packages are required for the script to run.

    General: gcc gcc-c++ git perl
    For non-static: openssl-dev[el] glibc-dev[el]
    For static: perl-core

You will need to install those packages manually

## Gathering data

1) Run the `system_prepare.sh`, make sure that you have `git` and `python`
already installed in your system.

2) Run the gatherer script for the OpenSSL component. The default dir is
`/minerva-results`. To see all available script options please use
`./components/openssl/gatherer.sh --help`

```bash
./components/openssl/gatherer.sh --gatherer components/openssl/time_sign_openssl.c [--static]
```

The gatherer by default will create 4 measurements files: measurements.csv
(for bit-size analysis), measurements-invert.csv (for inverted
bit-size analysis), measurements-hamming-weight.csv (for hamming weight
analysis) and measurements-hamming-weight-invert.csv (for inverted hamming
weight analysis).

3) *(optional)* if you want to combine data from multiple run use the following
command. For more info on the script use `--help`.

```bash
mkdir /minerva-all-results
PYTHONPATH=tlsfuzzer minerva-venv/bin/python tlsfuzzer/tlsfuzzer/combine.py \
    -o /minerva-all-results --long-format measurement0, measurement1, ...
```
## Analyzing data

Finally run analysis over the data. The By default the analysis script is trying
to calculate how many samples are needed to get confidence intervals of 1ns
and analyzing only that data. if you want to analyze all the data please use
`--no-smart-analysis`. For more info on the script use `--help`.

### Bit-size analysis

Analysis of the sizes of bit values. For bit size analysis we just use the
default measurements.csv file.

```bash
PYTHONPATH=tlsfuzzer minerva-venv/bin/python tlsfuzzer/tlsfuzzer/analysis.py \
    --bit-size --verbose -o dir-with-measurements/
```

### Inverted bit-size analysis

Analysis of the size of the inverted value. For bit size analysis we just use
measurements-invert.csv file (or leave it by default if the data were combined
and the name of the combined file is measurements.csv)

```bash
PYTHONPATH=tlsfuzzer minerva-venv/bin/python tlsfuzzer/tlsfuzzer/analysis.py \
    --bit-size --verbose -o dir-with-measurements/ \
    --measurements measurements-invert.csv
```

### Hamming weight analysis analysis

Analysis of the Hamming weight of the bit value. For bit size analysis we just
use measurements-hamming-weight.csv file (or leave it by default if the data
were combined and the name of the combined file is measurements.csv)

```bash
PYTHONPATH=tlsfuzzer minerva-venv/bin/python tlsfuzzer/tlsfuzzer/analysis.py \
    --Hamming-weight --verbose -o dir-with-measurements/ \
    --measurements measurements-hamming-weight.csv
```

### Inverted Hamming weight analysis analysis

Analysis of the Hamming weight of the inverted bit value. For bit size analysis
we just use measurements-hamming-weight.csv file (or leave it by default if the
data were combined and the name of the combined file is measurements.csv)

```bash
PYTHONPATH=tlsfuzzer minerva-venv/bin/python tlsfuzzer/tlsfuzzer/analysis.py \
    --Hamming-weight --verbose -o dir-with-measurements/ \
    --measurements measurements-hamming-weight-invert.csv
```