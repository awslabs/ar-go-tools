#!/usr/bin/python3
import yaml
import time
import shutil

DFLOW_PROBLEMS_KEY = 'dataflow-problems'
TAINT_TRACKING_KEY = 'taint-tracking'
SLICING_KEY = 'slicing'
SYNTACTIC_PROBLEMS_KEY = 'syntactic-problems'
COND_CHECKS_KEY = 'cond-checks'
STRUCT_INITS_KEY = 'struct-inits'

TOOL_TAINT = 'taint'
TOOL_BACKTRACE = 'backtrace'
TOOL_SYNTACTIC = 'syntactic'

def targets_of_config(config):
    targets = []
    for target in config["targets"]:
        targets.append(target["name"])
    return targets

def tool_and_tag_pairs(config):
    if DFLOW_PROBLEMS_KEY in config:
        problems = config[DFLOW_PROBLEMS_KEY]
        if TAINT_TRACKING_KEY in problems:
            for taint_tracking_problem in problems[TAINT_TRACKING_KEY]:
                yield TOOL_TAINT, taint_tracking_problem["tag"]
        if SLICING_KEY in problems:
            for slicing_problem in problems[SLICING_KEY]:
                yield TOOL_BACKTRACE, slicing_problem["tag"]
    if SYNTACTIC_PROBLEMS_KEY in config:
        problems = config[SYNTACTIC_PROBLEMS_KEY]
        if COND_CHECKS_KEY in problems:
            for cond_check_problem in problems[COND_CHECKS_KEY]:
                yield TOOL_SYNTACTIC, cond_check_problem["tag"]
        if STRUCT_INITS_KEY in problems:
            for struct_init_problem in problems[STRUCT_INITS_KEY]:
                yield TOOL_SYNTACTIC, struct_init_problem["tag"]

def tools_for_tag(config, target):
    if DFLOW_PROBLEMS_KEY in config:
        problems = config[DFLOW_PROBLEMS_KEY]
        if TAINT_TRACKING_KEY in problems:
            for taint_tracking_problem in problems[TAINT_TRACKING_KEY]:
                if target in taint_tracking_problem["targets"]:
                    yield TOOL_TAINT
                    break
        if SLICING_KEY in problems:
            for slicing_problem in problems[SLICING_KEY]:
                if target in slicing_problem["targets"]:
                    yield TOOL_BACKTRACE
                    break
    if SYNTACTIC_PROBLEMS_KEY in config:
        problems = config[SYNTACTIC_PROBLEMS_KEY]
        if COND_CHECKS_KEY in problems:
            for cond_check_problem in problems[COND_CHECKS_KEY]:
                if target in cond_check_problem["targets"]:
                    yield TOOL_SYNTACTIC
                    break
        if STRUCT_INITS_KEY in problems:
            for struct_init_problem in problems[STRUCT_INITS_KEY]:
                if target in struct_init_problem["targets"]:
                    yield TOOL_SYNTACTIC
                    break

# Run by tags: runs the tools for each tag
def run_by_tag(config):
    argot_output = config['options']['reports-dir']
    print(f"This script will run:")
    for tool, tag in tool_and_tag_pairs(config):
        print(f"> argot {tool} -config Tools/src/argot-config.yaml -tag {tag}")
    # Measure perf
    start_time = time.time()
    # Run argot
    for tool, tag in tool_and_tag_pairs(config):
        check_command = f"argot {tool} -config Tools/src/argot-config.yaml -tag {tag}"
        print(f"Running {check_command}")
        import subprocess
        try:
            subprocess.run(["argot", tool, "-config", "Tools/src/argot-config.yaml", "-tag", tag], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error while checking {tag}")
            print(e)
            exit(1)
        # If everything ran well, clean up the argot_output folder
        shutil.rmtree(argot_output, ignore_errors=True)

    end_time = time.time()
    print(f"\nTime taken: {end_time - start_time} seconds")


# Run by targets: runs the tools for each target
def run_by_target(config):
    argot_output = config['options']['reports-dir']
    targets = targets_of_config(config)
    print(f"This script will run:")
    for target in targets:
        for tool in set(tools_for_tag(config, target)):
            print(f"> argot {tool} -config Tools/src/argot-config.yaml -targets {target}")
    # Measure perf
    start_time = time.time()

    # Run argot
    for target in targets:
        for tool in set(tools_for_tag(config, target)):
            check_command = f"argot {tool} -config Tools/src/argot-config.yaml -targets {target}"
            print(f"\nRunning {check_command}")
            import subprocess
            try:
                subprocess.run(["argot", tool, "-config", "Tools/src/argot-config.yaml", "-targets", target], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error while checking {target}")
                print(e)
                exit(1)
            # If everything ran well, clean up the argot_output folder
            shutil.rmtree(argot_output, ignore_errors=True)

    end_time = time.time()
    print(f"\nTime taken: {end_time - start_time} seconds")


def main():
    with open("Tools/src/argot-config.yaml", "r") as f:
        config = yaml.safe_load(f)
    targets = targets_of_config(config)
    print("Targets:" + '\n + '.join(targets))
    print()
    argot_output = config['options']['reports-dir'] if 'options' in config else None
    if argot_output is None:
        print("No reports-dir found in argot-config.yaml, please add one")
        exit(1)
    else:
        print(f"Reports will be stored in {argot_output}\n")


    run_by_target(config)



# This file will be copied in the amazon-ssm-agent's root folder
if __name__ == "__main__":
    main()
