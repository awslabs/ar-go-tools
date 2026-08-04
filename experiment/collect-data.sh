#!/bin/bash

# Collect the experiment data for all 5 target repos.
#
# Runs entirely on the instance in one shot; nothing is copied back to the local machine
# automatically. For running/fetching one command at a time from your local machine instead
# (e.g. to iterate on eval-checker-* locally against already-produced raw data), see
# run-on-ec2.py / fetch-from-ec2.py.
#
# Each docker run is capped at 50GB RAM (--memory + --memory-swap set equal disables use of
# any swap inside the container, giving a hard cap): the instance has no swap configured.
#
# If a container hits the limit, the kernel OOM-kills it (not the host), the docker run exits
# nonzero, and this script logs it and moves on to the next step instead of hanging the whole run.
set -u
cd /home/ubuntu/ar-go-tools || exit 1
MEM_LIMIT=50g

rm -rf experiment/results
mkdir -p experiment/results

run() {
  local repo="$1"; shift
  # llm-summaries and generated-configs are mounted rather than living inside the image:
  # llm-summaries is not tracked in git, and generated-configs must persist across the separate
  # containers each step below runs in.
  docker run --rm --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" \
    -v "$(pwd)/experiment/results:/usr/src/app/experiment/results" \
    -v "$(pwd)/experiment/llm-summaries:/usr/src/app/experiment/llm-summaries" \
    -v "$(pwd)/experiment/generated-configs:/usr/src/app/experiment/generated-configs" \
    argot-experiment "$@"
}

for repo in amazon-ssm-agent badger govatar prometheus sample; do
  mkdir -p "experiment/results/$repo"

  # Each step below is its own container, so the configs must live on a mount to survive between
  # them. Without this, run-check finds no check-*-split-*.yaml at all.
  echo "=== $repo: generate-configs ==="
  run "$repo" generate-configs --repo "$repo" \
    || echo "$repo generate-configs FAILED (exit $?)"

  echo "=== $repo: run-check ==="
  run "$repo" run-check --repo "$repo" --out "results/$repo/check.json" \
    || echo "$repo run-check FAILED (exit $?)"

  echo "=== $repo: run-constructive ==="
  run "$repo" run-constructive --repo "$repo" --out "results/$repo/constructive.json" \
    || echo "$repo run-constructive FAILED (exit $?)"

  echo "=== $repo: eval-checker-precision ==="
  run "$repo" eval-checker-precision --repo "$repo" \
    --check-report "results/$repo/check.json" \
    --constructive-report "results/$repo/constructive.json" \
    --out "results/$repo/precision.json" \
    || echo "$repo eval-checker-precision FAILED (exit $?)"

  echo "=== $repo: eval-checker-efficiency ==="
  run "$repo" eval-checker-efficiency --repo "$repo" \
    --check-report "results/$repo/check.json" \
    --constructive-report "results/$repo/constructive.json" \
    --out "results/$repo/efficiency.json" \
    || echo "$repo eval-checker-efficiency FAILED (exit $?)"

  echo "=== $repo: eval-checker-ablation ==="
  run "$repo" eval-checker-ablation --repo "$repo" \
    --check-report "results/$repo/check.json" \
    --out "results/$repo/ablation.json" \
    || echo "$repo eval-checker-ablation FAILED (exit $?)"
done

echo ALL_DONE
