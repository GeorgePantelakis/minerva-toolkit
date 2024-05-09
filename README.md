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