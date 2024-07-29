Test scripts for OpenSSL implementation.

## Required

The following packages are required for the script to run.

    General: git python golang

You will need to install those packages manually

## Usage

### Gathering data

1) Run the `system_prepare.sh`, make sure that you have `git` and `python`
already installed in your system.

2) Run the gatherer script for the Golang component. The default dir is
`/minerva-results`. To see all available script options please use
`./components/openssl/gatherer.sh --help`

```bash
./components/openssl/gatherer.sh --gatherer components/openssl/time_sign_golang.go
```

3) *(optional)* if you want to combine data from multiple run use the following
command. For more info on the script use `--help`.

```bash
mkdir /minerva-all-results
PYTHONPATH=tlsfuzzer minerva-venv/bin/python tlsfuzzer/tlsfuzzer/combine.py \
    -o /minerva-all-results --long-format measurement0, measurement1, ...
```

4) Finally run analysis over the data. The By default the analysis script is trying
to calculate how many samples are needed to get confidence intervals of 1ns
and analyzing only that data. if you want to analyze all the data please use
`--no-smart-analysis`. For more info on the script use `--help`.

```bash
PYTHONPATH=tlsfuzzer minerva-venv/bin/python tlsfuzzer/tlsfuzzer/analysis.py \
    --bit-size --verbose -o dir-with-measurements/
```