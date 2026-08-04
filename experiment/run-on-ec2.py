#!/usr/bin/env python3

"""
Run a run_experiment.py command on a remote EC2 instance, inside the argot-experiment Docker
image (with the same 50GB memory cap as collect-data.sh).

Use this (with fetch-from-ec2.py) to iterate from your local machine: everything that changes
between runs is synced up and bind-mounted into the container, so testing a local change needs
neither a git push nor an image rebuild. To populate every repo/command in one shot on the
instance itself instead (nothing copied back automatically), use collect-data.sh.

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

What gets synced and mounted, and why each has to be rather than baked into the image:

  - argot itself, cross-compiled locally for linux/amd64. The image builds argot from a git
    clone, so without this a local change needs a push and an image rebuild.
  - run_experiment.py, and the eval-checker / find-interesting-methods sources it shells out to
    with `go run`.
  - llm-summaries, which is not tracked in git, so the clone cannot supply it. Without it
    generate-configs writes no check-llm-split-*.yaml.
  - argot-configs, ground-truth-summaries, interesting-methods: inputs that change as the
    experiment is developed.
  - generated-configs, so hand-written configs are available remotely, and because each command
    runs in its own container: configs written by generate-configs must outlive it to be visible
    to a later run-check.

generate-configs runs on the instance for the --repo named in the command, rather than syncing
locally generated configs and trusting them, because a config's project-root is a relative path
that has to resolve inside the container. It overwrites only the files it produces, so syncing
hand-written configs and regenerating do not conflict.

--no-sync skips all of the above and uses whatever is already on the instance, including the
image's own argot binary.

Transfers use a presigned S3 URL, matching fetch-from-ec2.py: the instance has no IAM role for
S3, so it only ever sees a short-lived signed URL. Local credentials need
s3:PutObject/GetObject/DeleteObject on the transfer bucket.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import boto3

REGION = "us-east-1"
TRANSFER_BUCKET = "argot-experiment-transfer-127797153327"
REMOTE_REPO_DIR = "/home/ubuntu/ar-go-tools"
EXPERIMENT_DIR = Path(__file__).parent
REPO_ROOT = EXPERIMENT_DIR.parent

# Paths under experiment/ mirrored up to the instance before each run, and bind-mounted into the
# container at the same relative location. Missing ones are skipped.
SYNC_PATHS = [
    "run_experiment.py",
    "argot-configs",
    "eval-checker",
    "find-interesting-methods",
    "ground-truth-summaries",
    "interesting-methods",
    "llm-summaries",
    "generated-configs",
]

# results is mounted but never synced up: the instance is what produces it.
MOUNT_PATHS = ["results", *SYNC_PATHS]

# Where the locally built argot is staged on the instance, and where it is mounted in the
# container. The image's `go install` puts argot in /go/bin (GOPATH=/go in the golang image).
REMOTE_ARGOT = f"{REMOTE_REPO_DIR}/experiment/.bin/argot"
CONTAINER_ARGOT = "/go/bin/argot"


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


def build_argot(dest: Path) -> None:
    """Cross-compile argot for the instance (linux/amd64) into dest."""
    print(f"Building argot for linux/amd64 -> {dest.name}...")
    env = dict(os.environ)
    env.update({"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"})
    subprocess.run(
        ["go", "build", "-o", str(dest), "./cmd/argot"],
        cwd=REPO_ROOT,
        check=True,
        env=env,
    )


def sync_up(ssm, s3, instance_id: str) -> None:
    """Copy the local argot binary and every present path in SYNC_PATHS to the instance.

    Extraction merges into what is already there rather than replacing it, so a file present
    remotely but not locally survives.
    """
    present = [p for p in SYNC_PATHS if (EXPERIMENT_DIR / p).exists()]
    missing = [p for p in SYNC_PATHS if p not in present]
    if missing:
        print(f"not syncing (absent locally): {', '.join(missing)}")

    with tempfile.TemporaryDirectory() as tmp:
        staged_argot = Path(tmp) / "argot"
        build_argot(staged_argot)

        archive = Path(tmp) / "sync.tgz"
        # -C per member so the binary lands at .bin/argot while the rest keep their own paths.
        # COPYFILE_DISABLE stops macOS tar emitting AppleDouble ._* companions, which would match
        # globs like *.yaml on the instance and be parsed as input.
        subprocess.run(
            [
                "tar",
                "czf",
                str(archive),
                "-C",
                str(EXPERIMENT_DIR),
                *present,
                "-C",
                tmp,
                "argot",
            ],
            check=True,
            env={**os.environ, "COPYFILE_DISABLE": "1"},
        )
        key = f"sync-{uuid.uuid4().hex}.tgz"
        size_mb = archive.stat().st_size / 1e6
        print(f"Syncing argot + {len(present)} path(s) ({size_mb:.1f} MB)...")
        s3.upload_file(str(archive), TRANSFER_BUCKET, key)

    try:
        download_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": TRANSFER_BUCKET, "Key": key},
            ExpiresIn=900,
        )
        remote_exp = f"{REMOTE_REPO_DIR}/experiment"
        run_ssm_command(
            ssm,
            instance_id,
            [
                f"set -e",
                f"cd {remote_exp}",
                f"mkdir -p .bin",
                f"curl -fsS -o /tmp/{key} '{download_url}'",
                f"tar xzf /tmp/{key} -C {remote_exp}",
                f"test -f {remote_exp}/argot",
                f"mv -f {remote_exp}/argot {REMOTE_ARGOT}",
                f"chmod +x {REMOTE_ARGOT}",
                f"chown -R ubuntu:ubuntu {remote_exp}",
                f"rm -f /tmp/{key}",
                f"echo synced argot: $({REMOTE_ARGOT} --version 2>&1 | head -1)",
            ],
        )
    finally:
        s3.delete_object(Bucket=TRANSFER_BUCKET, Key=key)


def repo_in_command(command: list) -> str:
    """Return the --repo argument in command, or "" if it names none."""
    for i, arg in enumerate(command):
        if arg == "--repo" and i + 1 < len(command):
            return command[i + 1]
        if arg.startswith("--repo="):
            return arg.split("=", 1)[1]
    return ""


def docker_run(quoted_cmd: str, with_local_argot: bool) -> str:
    mounts = [
        f"-v {REMOTE_REPO_DIR}/experiment/{p}:/usr/src/app/experiment/{p}"
        for p in MOUNT_PATHS
    ]
    if with_local_argot:
        mounts.append(f"-v {REMOTE_ARGOT}:{CONTAINER_ARGOT}")
    return (
        f"docker run --rm --memory=50g --memory-swap=50g {' '.join(mounts)} "
        f"argot-experiment {quoted_cmd}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("instance_id")
    parser.add_argument(
        "--no-sync",
        action="store_true",
        help="use what is already on the instance, including the image's own argot",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("no command given after --")

    ssm = boto3.client("ssm", region_name=REGION)
    synced = not args.no_sync

    if synced:
        s3 = boto3.client("s3", region_name=REGION)
        sync_up(ssm, s3, args.instance_id)

        repo = repo_in_command(command)
        if repo and command[0] != "generate-configs":
            print(f"Running generate-configs --repo {repo}...")
            run_ssm_command(
                ssm,
                args.instance_id,
                [
                    f"cd {REMOTE_REPO_DIR}/experiment",
                    docker_run(f"generate-configs --repo {repo}", synced),
                ],
            )

    quoted_cmd = " ".join(f"'{c}'" if " " in c else c for c in command)
    print(f"Running on {args.instance_id}: python3 run_experiment.py {quoted_cmd}")
    run_ssm_command(
        ssm,
        args.instance_id,
        [f"cd {REMOTE_REPO_DIR}/experiment", docker_run(quoted_cmd, synced)],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
