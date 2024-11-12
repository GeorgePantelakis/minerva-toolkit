Test scripts for GnuTLS implementation.

## Required

The following packages are required for the script to run.

    General: git gcc gcc-c++ python nss nss-tools gnutls-dev[el]

You will need to install those packages manually

## Scripts

All scripts should be run from the root of the minerva-toolkit directory

## Gathering data

1) Run the `system_prepare.sh`, make sure that you have `git` and `python`
already installed in your system.

2) Run the gatherer script for the GnuTLS component. The default dir is
`/minerva-results`. To see all available script options please use
`./components/gnutls/gatherer.sh --help`

```bash
./components/gnutls/gatherer.sh --gatherer components/gnutls/time_sign_gnutls.c
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

For more info read the
[analysis documentation](https://github.com/GeorgePantelakis/minerva-toolkit/blob/main/docs/Analysis.md)