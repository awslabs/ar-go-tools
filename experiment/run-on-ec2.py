#!/usr/bin/env python3

"""
Run a run_experiment.py command on a remote EC2 instance, inside the argot-experiment Docker
image (with the same 50GB memory cap as collect-data.sh).

Use this (with fetch-from-ec2.py) to run and pull back one command at a time from your local
machine, e.g. to iterate on eval-checker-* locally against already-produced raw data without
re-running argot. To populate every repo/command in one shot on the instance itself instead
(nothing copied back automatically), use collect-data.sh.

This only runs the command; it does not fetch any output back. Use fetch-from-ec2.py
separately to copy a resulting file to the local machine.

This script runs locally only (not inside the Docker image) and requires boto3: pip install
boto3.

Usage:
    python3 run-on-ec2.py <ec2-instance-id> -- <run_experiment.py command...>

Example:
    python3 run-on-ec2.py i-07f90b78bdeb63408 -- \\
        run-check --repo badger --out results/badger/check.json

Paths in the command (e.g. --out) are relative to /home/ubuntu/ar-go-tools/experiment/ on the
instance, matching collect-data.sh's convention.
"""

import argparse
import sys
import time

import boto3

REGION = "us-east-1"
REMOTE_REPO_DIR = "/home/ubuntu/ar-go-tools"


def run_ssm_command(
    ssm, instance_id: str, commands: list, timeout_seconds: int = 7200
) -> None:
    """Send a shell command via SSM and block until it completes, printing output and raising
    on failure."""
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=timeout_seconds,
    )
    command_id = resp["Command"]["CommandId"]

    while True:
        time.sleep(5)
        inv = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        status = inv["Status"]
        if status in ("Pending", "InProgress", "Delayed"):
            continue
        print(inv.get("StandardOutputContent", ""))
        if status != "Success":
            print(inv.get("StandardErrorContent", ""), file=sys.stderr)
            raise RuntimeError(f"SSM command failed with status {status}")
        return


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("instance_id")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("no command given after --")

    ssm = boto3.client("ssm", region_name=REGION)

    quoted_cmd = " ".join(f"'{c}'" if " " in c else c for c in command)
    print(f"Running on {args.instance_id}: python3 run_experiment.py {quoted_cmd}")
    run_ssm_command(
        ssm,
        args.instance_id,
        [
            f"cd {REMOTE_REPO_DIR}/experiment",
            f"docker run --rm --memory=50g --memory-swap=50g "
            f"-v {REMOTE_REPO_DIR}/experiment/results:/usr/src/app/experiment/results "
            f"argot-experiment {quoted_cmd}",
        ],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
