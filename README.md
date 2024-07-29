# Minerva Toolkit

A set of tools and instructions to check if a library is vulnerable to the
Minerva attack

## The vulnerability

A side-channel vulnerability in Elliptic Curve singing that allows for private
key extraction. See [CROCS Minerva page](https://minerva.crocs.fi.muni.cz/)
for details.

## Repo breakdown

`system_prepare.sh`: This is a preparation script that should be run before
every component gatherer. It checks if some dependencies are present and also
downloads tlsfuzzer which is later used for extraction and analysis of the data.

`components`: This directory contains all the example components. Any user can
create a new component. The directory should be named with the component name
and inside there should be a `gatherer.sh` script, at least one
`time_sign_{component}.*` harness for the component and a `README.md` file with
instructions on how to run the code for this component. It may also contain
any other file necessary for the smooth operation of the gatherer script.

`scripts`: This directory contain scripts that are useful to many components.

## Tips and tricks

### Tuning the machine

To have less noisy, and hence better, data from the gatherer and the ability
to use multiple processors to gather data in parallel, it is recommended to
tune the machine. More data can be found in
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html#hardware-selection)

## Interpretation of results

Detailed information about produced output is available in
[tlsfuzzer documentation](https://tlsfuzzer.readthedocs.io/en/latest/timing-analysis.html)
but what's most important is in the `analysis_results/report.txt`:

```
Skilling-Mack test p-value: 3.252825e-01
Sign test p-values (min, average, max): 2.28e-02, 5.63e-01, 1.00e+00
Wilcoxon test p-values (min, average, max): 1.12e-01, 5.65e-01, 1.00e+00
Used 477,400,983 out of 777,392,047 available data observations for results.
Implementation most likely not providing a timing side-channel signal.

----------------------------------------------------------------------------------------
| size | Sign test | Wilcoxon test |    Trimmed mean (5%)    |    Trimmed mean (45%)   |
|  384 |  8.93e-01 |    3.87e-01   | -1.097e-10 (±3.86e-10s) | -1.640e-11 (±2.56e-10s) |
|  383 |  5.06e-01 |    7.50e-01   |  2.958e-11 (±1.55e-10s) | -1.723e-11 (±1.23e-10s) |
|  382 |  5.51e-01 |    3.53e-01   | -5.726e-11 (±2.61e-10s) | -2.853e-11 (±1.81e-10s) |
|  381 |  9.60e-01 |    4.24e-01   | -5.299e-11 (±2.20e-10s) | -1.679e-11 (±1.80e-10s) |
|  380 |  9.08e-01 |    6.27e-01   | -6.287e-11 (±3.69e-10s) |  3.439e-12 (±2.57e-10s) |
|  379 |  5.01e-01 |    1.00e+00   |  5.687e-11 (±4.93e-10s) | -4.080e-11 (±3.24e-10s) |
|  378 |  2.28e-02 |    1.74e-01   |  2.193e-10 (±7.38e-10s) |  2.693e-10 (±5.35e-10s) |
|  377 |  7.60e-01 |    9.96e-01   |  1.171e-11 (±1.11e-09s) |  7.153e-11 (±7.57e-10s) |
|  376 |  8.51e-02 |    1.62e-01   |  4.677e-10 (±1.33e-09s) |  4.415e-10 (±9.43e-10s) |
|  375 |  5.86e-01 |    7.51e-01   |  5.485e-11 (±1.97e-09s) |  2.689e-10 (±1.20e-09s) |
----------------------------------------------------------------------------------------
```

The Skilling-Mack test p-value specifies how confident is the test in presence
of side channel in the entirely of the data (the smaller the p-value the more
confidant it is, i.e. a p-value of 1e-6 means 1 in a million chance that there
isn't a side-channel). The sign and Wilcoxon test p-values are for individual
nonce sizes (same principles for p-values as Skilling-Mack test apply). Next
line specifies how many data where used because of the smart analysis feature.
Last line in the first paragraph is the result of the testing.

Finally we have a table with the most important results for the first 10 (if
available) nonce sizes. The other important information are the 95% Confidence
Intervals reported in the parenthesis of trimmed mean, they specify how
sensitive is the script (in this case we have for 384 3.86e-10s so 386 ps)