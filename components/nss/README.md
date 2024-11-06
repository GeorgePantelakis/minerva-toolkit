Test scripts for NSS implementation.

## Required

The following packages are required for the script to run.

    General: git gcc gcc-c++ python nss nss-tools
    For non-static: nss-devel nspr-devel
    For static: mercurial ninja-build python3-pip zlib-devel glibc-static

You will need to install those packages manually

## Scripts

All scripts should be run from the root of the minerva-toolkit directory

## Gathering data

1) Run the `system_prepare.sh`, make sure that you have `git` and `python`
already installed in your system.

2) Run the gatherer script for the NSS component. The default dir is
`/minerva-results`. To see all available script options please use
`./components/nss/gatherer.sh --help`

```bash
./components/nss/gatherer.sh --gatherer components/nss/nss.c [--static]
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

For more info read the [Analysis](minerva-toolkit/blob/main/docs/Analysis.md)
documentation

Analysis of the Hamming weight of the inverted bit value. For bit size analysis
we just use measurements-hamming-weight.csv file (or leave it by default if the
data were combined and the name of the combined file is measurements.csv)

```bash
PYTHONPATH=tlsfuzzer minerva-venv/bin/python tlsfuzzer/tlsfuzzer/analysis.py \
    --Hamming-weight --verbose -o dir-with-measurements/ \
    --measurements measurements-hamming-weight-invert.csv
```