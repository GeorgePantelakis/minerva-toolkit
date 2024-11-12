# Analyzing data

When you have gathered the data you can run analysis over them. The By default
the analysis script is trying to calculate how many samples are needed to get
confidence intervals of 1ns and analyzing only that data. if you want to
analyze all the data please use `--no-smart-analysis`. For more info on the
script use `--help`.

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

### Interpreting the results

please check
https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html#interpreting-the-results