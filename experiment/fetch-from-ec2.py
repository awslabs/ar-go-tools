#!/usr/bin/env python3

"""
Fetch an entire experiment run directory from a remote EC2 instance back to the local machine.

Polls runs/<run-id>/run.json on the instance until its "status" field is "complete" or
"failed", then tars and downloads the entire runs/<run-id>/ directory. No SSM command IDs
needed — the run ID is the only identifier.

Transfers via a presigned S3 URL: the instance has no IAM role for direct S3 access, so it
only ever sees a short-lived signed URL. Local credentials need
s3:PutObject/GetObject/DeleteObject on the transfer bucket.

If runs/<run-id>/ already exists locally, fetched files are merged into it (existing files
are overwritten by the remote version).

This script runs locally only (not inside the Docker image) and requires boto3: pip install
boto3.

Usage:
    python3 fetch-from-ec2.py <ec2-instance-id> --run-id <run-id>

Example:
    python3 fetch-from-ec2.py i-07f90b78bdeb63408 --run-id 2026-08-13_14-25-30Z
"""

import argparse
import json
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
POLL_INTERVAL_SECONDS = 10


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("instance_id")
    parser.add_argument("--run-id", required=True, help="Which run to fetch")
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Skip polling run.json; assume the run is already complete and fetch immediately",
    )
    args = parser.parse_args()

    ssm = boto3.client("ssm", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)

    if not args.no_wait:
        poll_run_status(ssm, args.instance_id, args.run_id)

    fetch_run(ssm, s3, args.instance_id, args.run_id)
    return 0


def poll_run_status(ssm, instance_id: str, run_id: str) -> str:
    """Poll runs/<run-id>/run.json on the instance until status is terminal. Returns the
    final status ("complete" or "failed")."""
    remote_manifest = f"{REMOTE_REPO_DIR}/experiment/runs/{run_id}/run.json"
    print(f"Polling {run_id} on {instance_id}...")

    while True:
        try:
            output = run_ssm_command(ssm, instance_id, [f"cat '{remote_manifest}'"])
            manifest = json.loads(output)
            status = manifest.get("status", "")
            if status in ("complete", "failed"):
                print(f"Run {run_id} finished with status: {status}")
                return status
        except (RuntimeError, json.JSONDecodeError):
            # run.json doesn't exist yet or is being written; keep polling.
            pass

        time.sleep(POLL_INTERVAL_SECONDS)


def fetch_run(ssm, s3, instance_id: str, run_id: str) -> Path:
    """Tar the remote runs/<run-id>/ directory, upload via presigned URL, download and extract
    locally."""
    local_run_dir = EXPERIMENT_DIR / "runs" / run_id

    key = f"fetch-{uuid.uuid4().hex}.tgz"
    upload_url = s3.generate_presigned_url(
        "put_object", Params={"Bucket": TRANSFER_BUCKET, "Key": key}, ExpiresIn=900
    )

    print(f"Packing runs/{run_id}/ on {instance_id}...")
    run_ssm_command(
        ssm,
        instance_id,
        [
            "set -e",
            f"cd {REMOTE_REPO_DIR}/experiment",
            f"tar czf /tmp/{key} runs/{run_id}/",
            f"curl -sf -X PUT -T /tmp/{key} '{upload_url}'",
            f"rm -f /tmp/{key}",
        ],
        timeout_seconds=600,
    )

    with tempfile.TemporaryDirectory() as tmp:
        local_archive = Path(tmp) / key
        print(f"Downloading runs/{run_id}/...")
        s3.download_file(TRANSFER_BUCKET, key, str(local_archive))
        s3.delete_object(Bucket=TRANSFER_BUCKET, Key=key)

        local_run_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["tar", "xzf", str(local_archive), "-C", str(EXPERIMENT_DIR)],
            check=True,
        )

    print(f"Extracted to {local_run_dir}")
    return local_run_dir


def run_ssm_command(
    ssm, instance_id: str, commands: list, timeout_seconds: int = 120
) -> str:
    """Send a shell command via SSM and block until it completes, returning stdout."""
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=timeout_seconds,
    )
    command_id = resp["Command"]["CommandId"]
    while True:
        time.sleep(3)
        inv = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        status = inv["Status"]
        if status in ("Pending", "InProgress", "Delayed"):
            continue
        if status != "Success":
            raise RuntimeError(
                f"SSM command failed ({status}): {inv.get('StandardErrorContent', '')}"
            )
        return inv.get("StandardOutputContent", "")


if __name__ == "__main__":
    sys.exit(main())
