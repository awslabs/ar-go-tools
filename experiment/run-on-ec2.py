#!/usr/bin/env python3

"""
Run a run_experiment.py command on a remote EC2 instance, inside the argot-experiment Docker
image (with a 50GB memory cap).

Syncs local changes, rebuilds the image, and launches the command non-blocking. Prints a
fetch-from-ec2.py invocation to retrieve results once the run completes. fetch-from-ec2.py
polls runs/<run-id>/run.json on the instance for completion, so no SSM command IDs are needed.

--no-sync skips syncing and the image rebuild, using whatever is already on the instance.

This script runs locally only (not inside the Docker image) and requires boto3: pip install
boto3.

Usage:
    python3 run-on-ec2.py <ec2-instance-id> -- <run_experiment.py command...>

Example:
    python3 run-on-ec2.py i-07f90b78bdeb63408 -- \\
        run-check --repo badger --variant ground-truth --run-id 2026-08-13_14-25-30Z
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"
TRANSFER_BUCKET = "argot-experiment-transfer-127797153327"
REMOTE_REPO_DIR = "/home/ubuntu/ar-go-tools"
EXPERIMENT_DIR = Path(__file__).parent
REPO_ROOT = EXPERIMENT_DIR.parent

BEDROCK_ROLE_NAME = "argot-experiment-bedrock"
BEDROCK_POLICY_NAME = "bedrock-invoke"

# Paths synced to the instance. Dockerfile drives the image rebuild but isn't mounted.
SYNC_PATHS = [
    "run_experiment.py",
    "Dockerfile",
    "argot-configs",
    "eval-checker",
    "ground-truth-summaries",
    "interesting-methods",
]

# Bind-mounted into the container (everything synced except Dockerfile, plus runs/).
MOUNT_PATHS = [p for p in SYNC_PATHS if p != "Dockerfile"] + ["runs"]

REMOTE_BIN_DIR = f"{REMOTE_REPO_DIR}/experiment/.bin"
CONTAINER_BIN_DIR = "/go/bin"

# Stable container name so we can docker cp / docker rm it after the run, and a host
# directory that receives the copied-out container outputs for SSH inspection.
CONTAINER_NAME = "argot-experiment-run"
HOST_OUTPUT_DIR = f"{REMOTE_REPO_DIR}/experiment/container-output"

# The two output locations worth keeping from the container: the whole experiment tree,
# and the per-repo argot logs written under payload/public-repos-checks/<repo>/logs.
CONTAINER_EXPERIMENT_DIR = "/usr/src/app/experiment"
CONTAINER_REPOS_DIR = "/usr/src/app/payload/public-repos-checks"

LOCAL_BINARIES = {
    "argot": "./cmd/argot",
    "eval-checker": "./experiment/eval-checker",
    "argot-mcp-server": "./cmd/argot-mcp-server",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("instance_id")
    parser.add_argument(
        "--no-sync",
        action="store_true",
        help="use what is already on the instance, including the current image (skips rebuild)",
    )

    argv = sys.argv[1:]
    if "--" in argv:
        split = argv.index("--")
        own_args, command = argv[:split], argv[split + 1 :]
    else:
        own_args, command = argv, []

    args = parser.parse_args(own_args)
    if not command:
        parser.error("no command given after --")

    ssm = boto3.client("ssm", region_name=REGION)
    synced = not args.no_sync

    iam = boto3.client("iam", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    ensure_bedrock_access(iam, ec2, args.instance_id)

    if synced:
        s3 = boto3.client("s3", region_name=REGION)
        sync_up(ssm, s3, args.instance_id)

    quoted_cmd = " ".join(f"'{c}'" if " " in c else c for c in command)
    print(f"Running on {args.instance_id}: python3 run_experiment.py {quoted_cmd}")

    command_id = send_ssm_command(
        ssm,
        args.instance_id,
        [
            f"mkdir -p {REMOTE_REPO_DIR}/experiment/runs",
            f"cd {REMOTE_REPO_DIR}/experiment",
            docker_run(quoted_cmd, synced),
            # Docker runs each experiment in an isolated container so persist the output files by:
            # (1) copying the whole experiment tree and (2) copying each repo's logs/ directory.
            # This works in case of a failure too.
            f"mkdir -p {HOST_OUTPUT_DIR}/experiment {HOST_OUTPUT_DIR}/repo-logs",
            f"docker cp {CONTAINER_NAME}:{CONTAINER_EXPERIMENT_DIR}/. "
            f"{HOST_OUTPUT_DIR}/experiment/ || true",
            f"for repo in $(ls {REMOTE_REPO_DIR}/experiment/argot-configs); do "
            f"mkdir -p {HOST_OUTPUT_DIR}/repo-logs/$repo; "
            f"docker cp {CONTAINER_NAME}:{CONTAINER_REPOS_DIR}/$repo/logs/. "
            f"{HOST_OUTPUT_DIR}/repo-logs/$repo/ 2>/dev/null || true; "
            f"done",
            f"chown -R ubuntu:ubuntu {HOST_OUTPUT_DIR} || true",
            f"docker rm -f {CONTAINER_NAME} >/dev/null 2>&1 || true",
        ],
    )
    print(f"Launched, not waiting for completion. Command ID: {command_id}")

    # Print fetch hint
    run_id = ""
    if "--run-id" in command:
        run_id = command[command.index("--run-id") + 1]
    run_id_part = run_id if run_id else "<RUN_ID>"
    print(
        f"Fetch the result with:\npython3 fetch-from-ec2.py {args.instance_id} --run-id {run_id_part}"
    )
    print(
        f"Container outputs are also copied to {HOST_OUTPUT_DIR} on the instance "
        f"(visible over SSH): experiment/ (full experiment tree) and repo-logs/<repo>/ "
        f"(per-repo argot logs), populated after the run finishes."
    )
    return 0


# ---------------------------------------------------------------------------
# Sync and Docker
# ---------------------------------------------------------------------------


def sync_up(ssm, s3, instance_id: str) -> None:
    present = [p for p in SYNC_PATHS if (EXPERIMENT_DIR / p).exists()]
    missing = [p for p in SYNC_PATHS if p not in present]
    if missing:
        print(f"not syncing (absent locally): {', '.join(missing)}")

    with tempfile.TemporaryDirectory() as tmp:
        staged_bin = Path(tmp) / ".bin"
        staged_bin.mkdir()
        build_binaries(staged_bin)

        archive = Path(tmp) / "sync.tgz"
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
                ".bin",
            ],
            check=True,
            env={**os.environ, "COPYFILE_DISABLE": "1"},
        )
        key = f"sync-{uuid.uuid4().hex}.tgz"
        size_mb = archive.stat().st_size / 1e6
        print(
            f"Syncing {len(LOCAL_BINARIES)} binaries + {len(present)} path(s) "
            f"({size_mb:.1f} MB)..."
        )
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
                "set -e",
                f"cd {remote_exp}",
                f"curl -fsS -o /tmp/{key} '{download_url}'",
                f"tar xzf /tmp/{key} -C {remote_exp}",
                *(f"test -f {REMOTE_BIN_DIR}/{name}" for name in LOCAL_BINARIES),
                f"chmod +x {REMOTE_BIN_DIR}/*",
                f"chown -R ubuntu:ubuntu {remote_exp}",
                f"rm -f /tmp/{key}",
                f"echo synced argot: $({REMOTE_BIN_DIR}/argot --version 2>&1 | head -1)",
            ],
        )
    finally:
        s3.delete_object(Bucket=TRANSFER_BUCKET, Key=key)

    print("Rebuilding the argot-experiment Docker image...")
    run_ssm_command(
        ssm,
        instance_id,
        [
            "set -e",
            f"cd {REMOTE_REPO_DIR}/experiment",
            "docker build --no-cache -t argot-experiment -f Dockerfile .",
        ],
        timeout_seconds=1800,
    )


def docker_run(quoted_cmd: str, with_local_binaries: bool) -> str:
    mounts = [
        f"-v {REMOTE_REPO_DIR}/experiment/{p}:/usr/src/app/experiment/{p}"
        for p in MOUNT_PATHS
    ]
    env = []
    if with_local_binaries:
        mounts += [
            f"-v {REMOTE_BIN_DIR}/{name}:{CONTAINER_BIN_DIR}/{name}"
            for name in LOCAL_BINARIES
        ]
        env.append(f"-e EVAL_CHECKER_BIN={CONTAINER_BIN_DIR}/eval-checker")
    return (
        f"docker rm -f {CONTAINER_NAME} >/dev/null 2>&1; "
        f"docker run --name {CONTAINER_NAME} --memory=50g --memory-swap=50g "
        f"{' '.join(mounts)} {' '.join(env)} argot-experiment {quoted_cmd}"
    )


def build_binaries(dest_dir: Path) -> None:
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
    for name, pkg in LOCAL_BINARIES.items():
        print(f"Building {name} for linux/amd64...")
        subprocess.run(
            ["go", "build", "-o", str(dest_dir / name), pkg],
            cwd=REPO_ROOT,
            check=True,
            env=env,
        )


# ---------------------------------------------------------------------------
# Bedrock IAM setup
# ---------------------------------------------------------------------------


EC2_ASSUME_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
BEDROCK_INVOKE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                    "bedrock:ListInferenceProfiles",
                    "bedrock:GetInferenceProfile",
                ],
                "Resource": "*",
            }
        ],
    }
)


def ensure_bedrock_access(iam, ec2, instance_id: str) -> None:
    try:
        iam.get_role(RoleName=BEDROCK_ROLE_NAME)
        print(f"IAM role {BEDROCK_ROLE_NAME} already exists")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
        print(f"Creating IAM role {BEDROCK_ROLE_NAME}...")
        iam.create_role(
            RoleName=BEDROCK_ROLE_NAME,
            AssumeRolePolicyDocument=EC2_ASSUME_ROLE_POLICY,
        )

    iam.put_role_policy(
        RoleName=BEDROCK_ROLE_NAME,
        PolicyName=BEDROCK_POLICY_NAME,
        PolicyDocument=BEDROCK_INVOKE_POLICY,
    )

    try:
        iam.get_instance_profile(InstanceProfileName=BEDROCK_ROLE_NAME)
        print(f"Instance profile {BEDROCK_ROLE_NAME} already exists")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
        print(f"Creating instance profile {BEDROCK_ROLE_NAME}...")
        iam.create_instance_profile(InstanceProfileName=BEDROCK_ROLE_NAME)
        iam.add_role_to_instance_profile(
            InstanceProfileName=BEDROCK_ROLE_NAME, RoleName=BEDROCK_ROLE_NAME
        )
        time.sleep(10)

    associations = ec2.describe_iam_instance_profile_associations(
        Filters=[
            {"Name": "instance-id", "Values": [instance_id]},
            {"Name": "state", "Values": ["associating", "associated"]},
        ]
    )["IamInstanceProfileAssociations"]
    attached_names = {
        a["IamInstanceProfile"]["Arn"].rsplit("/", 1)[-1] for a in associations
    }
    if BEDROCK_ROLE_NAME in attached_names:
        print(f"Instance profile {BEDROCK_ROLE_NAME} already attached to {instance_id}")
        return

    for a in associations:
        print(
            f"Replacing existing instance profile "
            f"{a['IamInstanceProfile']['Arn']} on {instance_id}..."
        )
        ec2.replace_iam_instance_profile_association(
            AssociationId=a["AssociationId"],
            IamInstanceProfile={"Name": BEDROCK_ROLE_NAME},
        )
        return

    print(f"Attaching instance profile {BEDROCK_ROLE_NAME} to {instance_id}...")
    ec2.associate_iam_instance_profile(
        IamInstanceProfile={"Name": BEDROCK_ROLE_NAME}, InstanceId=instance_id
    )


# ---------------------------------------------------------------------------
# SSM helpers
# ---------------------------------------------------------------------------


def send_ssm_command(
    ssm, instance_id: str, commands: list, timeout_seconds: int = 7200
) -> str:
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=timeout_seconds,
    )
    return resp["Command"]["CommandId"]


def run_ssm_command(
    ssm, instance_id: str, commands: list, timeout_seconds: int = 7200
) -> None:
    command_id = send_ssm_command(ssm, instance_id, commands, timeout_seconds)
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


if __name__ == "__main__":
    sys.exit(main())
