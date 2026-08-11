#!/usr/bin/env python3

"""
Copy a file that already exists on a remote EC2 instance (e.g. a run_experiment.py output
written by run-on-ec2.py or collect-data.sh) back to the local machine.

Does not run anything remotely -- use run-on-ec2.py first to produce the file if it doesn't
exist yet. Transfers via a presigned S3 PUT URL generated locally: the instance has no IAM
role for direct S3 access (by design, minimal privilege), so it only ever sees a short-lived
signed URL, never real AWS credentials. Local credentials need s3:PutObject/GetObject/
DeleteObject on the transfer bucket.

This script runs locally only (not inside the Docker image) and requires boto3: pip install
boto3.

Usage:
    python3 fetch-from-ec2.py <ec2-instance-id> <repo> <result-type>

result-type is one of the RESULT_TYPES below, matching the
results/<repo>/<result-type>-results.json path convention used by collect-data.sh and
run-on-ec2.py on both sides (remote and local).

Example:
    python3 fetch-from-ec2.py i-07f90b78bdeb63408 badger run-check-ground-truth
"""

import argparse
import sys
import time
import uuid
from pathlib import Path

import boto3

REGION = "us-east-1"
TRANSFER_BUCKET = "argot-experiment-transfer-127797153327"
REMOTE_REPO_DIR = "/home/ubuntu/ar-go-tools"
EXPERIMENT_DIR = Path(__file__).parent

RESULT_TYPES = [
    "run-check-ground-truth",
    "run-check-llm",
    "run-constructive",
    "run-llm-summarization",
    "run-taint-baseline",
    "run-taint-ground-truth",
    "run-taint-llm",
    "eval-checker-precision",
    "eval-checker-efficiency",
    "eval-checker-ablation",
    "eval-llm-effectiveness",
    "eval-workflow-efficiency",
]
REPOS = ["amazon-ssm-agent", "badger", "govatar", "prometheus", "sample"]


def run_ssm_command(
    ssm, instance_id: str, commands: list, timeout_seconds: int = 900
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
    parser.add_argument("repo", choices=REPOS)
    parser.add_argument("result_type", choices=RESULT_TYPES)
    args = parser.parse_args()

    relative_path = f"results/{args.repo}/{args.result_type}-results.json"

    ssm = boto3.client("ssm", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)

    key = f"fetch-{uuid.uuid4().hex}.json"
    upload_url = s3.generate_presigned_url(
        "put_object", Params={"Bucket": TRANSFER_BUCKET, "Key": key}, ExpiresIn=900
    )
    print(
        f"Uploading {relative_path} from {args.instance_id} to S3 via presigned URL..."
    )
    run_ssm_command(
        ssm,
        args.instance_id,
        [
            f"curl -sf -X PUT -T '{REMOTE_REPO_DIR}/experiment/{relative_path}' "
            f"'{upload_url}'"
        ],
    )

    local_out = EXPERIMENT_DIR / relative_path
    local_out.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading to {local_out}...")
    s3.download_file(TRANSFER_BUCKET, key, str(local_out))
    s3.delete_object(Bucket=TRANSFER_BUCKET, Key=key)

    print(f"Wrote {local_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
