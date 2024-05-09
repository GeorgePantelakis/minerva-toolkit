import subprocess
import os
import sys
import shutil
import getopt
import ecdsa
import functools
import re

from os.path import join
from tlslite.utils.compat import b2a_hex, int_to_bytes

results_dir = None
number_of_samples = 1000000
size_of_data = 32
verbose = False
run_in_32 = False
gatherer = "time_sign.c"
component = "openssl"
gcc_flags = ''
keep_flags = False

data_file_name = "data"
sig_file_name = "sigs"
time_file_name = "times"
priv_key_file_name_base = "priv_key"
pub_key_file_name_base = "pub_key"
pub_cert_file_name = "pub_cert.cert"
pcks_12_file_name = "key.p12"

def help_msg():
    """Print help message."""
    print(f"Usage: {sys.argv[0]} [-o output] [-c curve]")
    print( " -o output           Directory where to place results (required)")
    print( " -c curve            The curve by name e.g NIST256p, NIST384p etc. (required)")
    print( " -n number           Number of samples to create (default: 1000000)")
    print( " -s number           Size of each data block (default: 32)")
    print( " -v                  Prints a more verbose output")
    print( " --run-in-32         Runs gatherer in 32 bit")
    print( " --gatherer path     Specify a different path for the c program gatherer.")
    print(f"                     (Default {gatherer})")
    print( " --component comp    Specify the component you want to use.")
    print(f"                     (Default openssl)")
    print( " --list-components   Prints a list with all available components and exits")
    print(f" --gcc-flags string  Flags to add on gcc when compiling.")
    print(f" --keep-flags        Keeps default flags on top of the flags given")
    print(f"                     by gcc-flags option.")
    print( " --help              Displays this message")

def clear_previous_run_files():
    if results_dir and not os.path.exists(results_dir):
        os.mkdir(results_dir)
    else:
        for filename in os.listdir(results_dir):
            file_path = join(results_dir, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except:
                pass

def create_new_ecdsa_keys(curve):
    key = ecdsa.SigningKey.generate(curve=curve)

    with open(join(results_dir, priv_key_file_name_base + ".pem"), "wb") as f:
        f.write(key.to_pem(format="pkcs8"))

    with open(join(results_dir, priv_key_file_name_base + ".der"), "wb") as f:
        f.write(key.to_der(format="pkcs8"))

    public_key = key.verifying_key

    with open(join(results_dir, pub_key_file_name_base + ".pem"), "wb") as f:
        f.write(public_key.to_pem())

    with open(join(results_dir, pub_key_file_name_base + ".der"), "wb") as f:
        f.write(public_key.to_der())

    if component == "libgcrypt":
        curve_name = key.curve.name
        secret_in_hex = b2a_hex(int_to_bytes(key.privkey.secret_multiplier))

        if "NIST" in curve_name:
            curve_numbers = re.findall(r'\d{3}', curve_name)
            curve_name = "NIST P-{0}".format(curve_numbers[0])

        with open(
            join(results_dir, priv_key_file_name_base + ".txt"), "w"
        ) as f:
            f.write(
                "curve={0}\nd={1}\nb={2}\n".format(
                    curve_name, secret_in_hex, key.curve.baselen
                )
            )

def generate_random_data():
    count_of_1024 = (size_of_data * number_of_samples) // 1024
    rest_of_data_needed = (size_of_data * number_of_samples) % 1024

    subprocess.run(f'dd if=/dev/urandom of={join(results_dir, data_file_name)} bs=1024 count={count_of_1024} &> /dev/null', shell=True)

    if rest_of_data_needed != 0:
        subprocess.run(f'dd if=/dev/urandom of={join(results_dir, data_file_name)} bs=1 count={rest_of_data_needed} conv=notrunc oflag=append &> /dev/null', shell=True)


def compile_and_run_c_code():
    global gcc_flags

    priv_key_location = priv_key_file_name_base + ".pem"
    commands = []

    if component == 'nss':
        priv_key_location = 'nssdb'
        commands.extend([
            f'openssl req -x509 -key {join(results_dir, priv_key_file_name_base + ".pem")} -out {join(results_dir, pub_cert_file_name)} \
                -days 3650 -nodes -subj "/C=CZ/CN=localhost"',
            f'openssl pkcs12 -export -inkey {join(results_dir, priv_key_file_name_base + ".pem")} -in {join(results_dir, pub_cert_file_name)} \
                -out {join(results_dir, pcks_12_file_name)} -passout pass:',
            f'mkdir {join(results_dir, "nssdb")}',
            f'certutil -N -d {join(results_dir, "nssdb")} --empty-password',
            f'pk12util -d {join(results_dir, "nssdb")} -i {join(results_dir, pcks_12_file_name)} -W ""',
        ])
    elif component == "libgcrypt":
        priv_key_location = priv_key_file_name_base + ".txt"

    if not gcc_flags or keep_flags:
        if component == 'openssl':
            gcc_flags += " -lssl -lcrypto"
        elif component == 'nss':
            gcc_flags += " $(nss-config --libs) $(nss-config --cflags) $(nspr-config --libs) $(nspr-config --cflags)"
        elif component == 'gnutls':
            gcc_flags += " -lgnutls"
        elif component == "libgcrypt":
            gcc_flags += " -lgcrypt -lgpg-error"

    if run_in_32:
        gcc_flags += " -m32"

    commands.extend([
        f'gcc {gatherer} -o {join(results_dir, "time_sign")} -w {gcc_flags}',
        f'echo Linked libraries for {join(results_dir, "time_sign")}:',
        f'ldd {join(results_dir, "time_sign")}',
        f'{join(results_dir, "time_sign")} -i {join(results_dir, data_file_name)} \
            -o {join(results_dir, sig_file_name)} -t {join(results_dir, time_file_name)} \
            -k {join(results_dir, priv_key_location)} -s {size_of_data}'
    ])

    return commands

def run_python_code():
    priv_key_location = priv_key_file_name_base + ".pem"

    commands = [
        f'python {gatherer} -i {join(results_dir, data_file_name)} \
            -o {join(results_dir, sig_file_name)} -t {join(results_dir, time_file_name)} \
            -k {join(results_dir, priv_key_location)} -s {size_of_data}'
    ]

    return commands

def run_go_code():
    priv_key_location = priv_key_file_name_base + ".pem"

    commands = [
        f'go run {gatherer} -i {join(results_dir, data_file_name)} \
            -o {join(results_dir, sig_file_name)} -t {join(results_dir, time_file_name)} \
            -k {join(results_dir, priv_key_location)} -s {size_of_data}'
    ]

    return commands

def main():
    global results_dir
    global number_of_samples
    global size_of_data
    global verbose
    global run_in_32
    global gatherer
    global component
    global gcc_flags
    global keep_flags
    curve_name = None

    component_to_test_func = [
        (["openssl", "nss", "gnutls", "libgcrypt"], compile_and_run_c_code),
        (["py-ecdsa"], run_python_code),
        (["golang"], run_go_code)
    ]

    all_available_components = functools.reduce(
        lambda a, b: (a[0] + b[0], None), component_to_test_func
    )[0]

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "o:c:n:s:v", ["help", "run-in-32",
                                                "gatherer=", "component=",
                                                "gcc-flags=", "keep-flags",
                                                "list-components"])
    for opt, arg in opts:
        if opt == '-o':
            results_dir = arg
        elif opt == "-c":
            curve_name = arg
        elif opt == "-n":
            number_of_samples = int(arg)
        elif opt == "-s":
            size_of_data = int(arg)
        elif opt == "-v":
            verbose = True
        elif opt == "--run-in-32":
            run_in_32 = True
        elif opt == "--gatherer":
            gatherer = arg
        elif opt == "--component":
            component = arg.lower()
        elif opt == "--gcc-flags":
            gcc_flags = arg
        elif opt == "--keep-flags":
            keep_flags = True
        elif opt == "--list-components":
            print("Available components to test:")
            for i, component in enumerate(all_available_components):
                print(" {0}) {1}".format(i + 1, component))
            sys.exit(0)
        elif opt == "--help":
            help_msg()
            sys.exit(0)

    if args:
        raise ValueError(
            f"Unexpected arguments: {args}")

    if not all([results_dir, curve_name]):
        raise ValueError(
            "Specifying curve and output is mandatory")

    try:
        curve = ecdsa.curves.curve_by_name(curve_name)
    except:
        raise ValueError(
            f"Curve {curve_name} is not a known curve")

    if not component in all_available_components:
        raise ValueError(
            f"Component must be " +
            ", ".join(all_available_components[:-1]) +
            ", or " + all_available_components[-1]
        )

    if verbose:
        print(f"Running for {number_of_samples} samples")
    clear_previous_run_files()
    if verbose:
        print ('Creating new ECDSA keys...')
    create_new_ecdsa_keys(curve)
    if verbose:
        print ('Generating data...')
    generate_random_data()
    if verbose:
        print ('Signing data...')

    commands = None
    for item in component_to_test_func:
        if component in item[0]:
            commands = item[1]()
            break

    for command in commands:
        p = subprocess.run(command, shell=True)
        if p.returncode != 0 and not 'ldd' in command:
            print(command)
            parts = command.split(' ')
            command_name = " ".join(
                parts[:2] if not parts[1][0].startswith('-') else parts[:1]
            )
            print(f"There was an error on command \"{command_name} [options]\" ({p.returncode}).")
            exit(1)

if __name__ == "__main__":
    main()