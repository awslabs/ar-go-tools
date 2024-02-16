#!/usr/bin/env python3

# NOTE Requires the pyyaml library. Install via `python3 -m pip install pyyaml`.

import argparse
import urllib.request
import yaml

DESCRIPTION = """
Adds sinks to the specified config file with capabilities.
WARNING This will modify the config file.
"""

CAPABILITIES = {
    "CAPABILITY_FILES",
    "CAPABILITY_OPERATING_SYSTEM",
    "CAPABILITY_NETWORK",
    "CAPABILITY_MODIFY_SYSTEM_STATE",
    "CAPABILITY_ARBITRARY_EXECUTION",
    "CAPABILITY_EXEC",
    "CAPABILITIY_SYSTEM_CALLS",
    "CAPABILITY_REFLECT",
    "CAPABILITY_RUNTIME"
}

def main():
    parser = argparse.ArgumentParser(
        prog="add-capability-sinks",
        description=DESCRIPTION,
    )
    parser.add_argument("--config-file")
    args = parser.parse_args()
    config_file = args.config_file
    if config_file is None:
        parser.print_help()
        return

    # Capabilities are hardcoded for now
    fns = get_capability_fns(CAPABILITIES)
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)

    parsed_sinks = parse_sinks(fns)
    n = add_config_sinks(config, parsed_sinks)

    with open(config_file, "w") as f:
        yaml.dump(config, f)

    print(f"Successfully added {n} new sink(s) to config file {config_file}")

def get_capability_fns(capabilities):
    """
    Returns a string containing the Go standard library functions with a
    capability in capabilities.
    """
    capabilities_file_url = "https://raw.githubusercontent.com/google/capslock/main/interesting/interesting.cm"
    f = urllib.request.urlopen(capabilities_file_url)
    fns = []
    for line in f:
        line = line.decode("utf-8").strip()
        line = line.split(" ")
        if len(line) == 3:
            fn, capability = line[1], line[2]
            if capability in capabilities:
                fns.append(fn)
    return fns

def add_config_sinks(config, parsed_sinks):
    """
    Adds parsed_sinks to the sinks in config.
    Returns the number of sinks added.
    """
    # NOTE this only works for a single taint-tracking-problem for now
    sinks = config["taint-tracking-problems"][0]["sinks"]
    # Hardcode print functions because they perform I/O as well
    parsed_sinks += [
        {"package": "fmt", "method": "Print.*"}
    ]
    n = 0
    for parsed_sink in parsed_sinks:
        if parsed_sink not in sinks:
            sinks.append(parsed_sink)
            n += 1
    return n

def parse_sinks(fns):
    """
    Parses a list of fns into Argot config code identifiers.
    """
    return [parse_sink(fn) for fn in fns]

def parse_sink(fn):
    """
    Parses fn (function or package string from capslock interesting.cm file)
    into an Argot config code identifier.
    """
    split = fn.split(".")
    # e.g. unsafe
    if len(split) == 1:
        pkg = f"{split[0]}"
        fn = ".*"
    # e.g. net.Dial
    elif len(split) == 2:
        pkg = f"{split[0]}"
        fn = f"{split[1]}$"
    # e.g. (*os.File).Read
    elif len(split) == 3:
        pkg = split[0].replace("(*", "")
        pkg = f"{pkg}"
        fn = f"{split[2]}$"

    return {"package": pkg, "method": fn}

if __name__ == "__main__":
    main()
