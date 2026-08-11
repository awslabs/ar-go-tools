#!/usr/bin/env python3
"""
Experiment runner for the dataflow-soundness-checker paper's evaluation.

Producer commands run argot and write its raw JSON output to a file you name:
    run-check          run the soundness checker against a summaries file
    run-constructive    run the constructive (naive) approach against a list of methods

Consumer (eval-*) commands are pure functions over already-produced JSON files -- they
never invoke argot themselves, so re-running an eval-* command (or running several of them
in sequence) never re-runs the (possibly expensive) producer commands:
    eval-checker-precision   RQ: checker-precision
    eval-checker-efficiency  RQ: checker-efficiency
    eval-checker-ablation    RQ: checker-ablation

--repo is mandatory for every command. To run a command across multiple repos, loop over
this script from the shell.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
from rich.console import Console

console = Console()

EXPERIMENT_DIR = Path(__file__).parent
REPOS_BASE_DIR = EXPERIMENT_DIR.parent / "payload" / "public-repos-checks"
GROUND_TRUTH_DIR = EXPERIMENT_DIR / "ground-truth-summaries"
LLM_SUMMARIES_DIR = EXPERIMENT_DIR / "llm-summaries"
# Per-repo build target + taint-tracking-problems, mirroring ground-truth-summaries/<repo>/*.yaml's
# layout. See _base_config/_taint_specs.
ARGOT_CONFIGS_DIR = EXPERIMENT_DIR / "argot-configs"
# Generated, read-only, per-task argot-config.yaml files -- see _generate_configs_for_repo.
GENERATED_CONFIGS_DIR = EXPERIMENT_DIR / "generated-configs"
INTERESTING_METHODS_DIR = EXPERIMENT_DIR / "interesting-methods"
FIND_INTERESTING_METHODS_DIR = EXPERIMENT_DIR / "find-interesting-methods"
# A prebuilt eval-checker to use instead of `go run`. run-on-ec2.py sets this so that eval-checker
# runs the local tree's analysis/summaries code: `go run` inside the container would compile
# against the clone baked into the image instead.
EVAL_CHECKER_BIN = os.environ.get("EVAL_CHECKER_BIN")


@dataclass(frozen=True)
class RepoInfo:
    """Everything needed to check out a target repo at a pinned commit. url/commit are pinned
    for reproducibility (see Dockerfile)."""

    url: str
    commit: str


# The 5 repos used for the checker-precision (RQ1) ground-truth evaluation.
REPOS: Dict[str, RepoInfo] = {
    "amazon-ssm-agent": RepoInfo(
        url="https://github.com/aws/amazon-ssm-agent.git",
        commit="ef5df636f7035bb1e3e325fab519379715678033",
    ),
    "badger": RepoInfo(
        url="https://github.com/dgraph-io/badger.git",
        commit="a700dc3b6332e2351674f34f841233541568f782",
    ),
    "govatar": RepoInfo(
        url="https://github.com/o1egl/govatar.git",
        commit="31618c34a7ae828c61629e022b1654e4ec552628",
    ),
    "prometheus": RepoInfo(
        url="https://github.com/prometheus/client_golang.git",
        commit="7ba246a648ca4e294ca008d95b6fcc8df2f9c255",
    ),
    "sample": RepoInfo(
        url="",  # local-only sample program, tracked directly in this repo; not cloned
        commit="",
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p = subparsers.add_parser(
        "generate-configs",
        help="(Re)generate the fixed, read-only argot-config.yaml files in "
        "generated-configs/<repo>/ for repo (or every repo, if --repo is omitted)",
    )
    p.add_argument("--repo", choices=sorted(REPOS))
    p.set_defaults(func=cmd_generate_configs)

    p = subparsers.add_parser(
        "run-check", help="Run the soundness checker against a summaries file"
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--variant",
        required=True,
        choices=["ground-truth", "llm"],
        help="Which summaries to check: ground-truth (every file in "
        "experiment/ground-truth-summaries/<repo>/) or llm "
        "(experiment/llm-summaries/<repo>/summaries.yaml)",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_run_check)

    p = subparsers.add_parser(
        "run-constructive",
        help="Run the constructive (naive) approach against a list of methods",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--methods",
        type=Path,
        help="Path to a single interesting-methods summaries YAML "
        "(default: every file in experiment/ground-truth-summaries/<repo>/)",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_run_constructive)

    p = subparsers.add_parser(
        "run-llm-summarization",
        help="Run the LLM agent (argot-summarize) to generate dataflow summaries for repo's "
        "to_summarize.json",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--target",
        help="Target name to load (default: the repo's first argot-config.yaml target)",
    )
    p.add_argument("--model", default="anthropic.claude-sonnet-5")
    p.add_argument(
        "--inference-profile",
        help="Bedrock inference profile ARN/ID (skips auto-detection if set)",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_run_llm_summarization)

    p = subparsers.add_parser(
        "run-taint",
        help="Run the taint analysis using one of repo's fixed generated configs",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--variant",
        choices=["baseline", "ground-truth", "llm"],
        default="baseline",
        help="Which generated-configs/<repo>/taint-*.yaml to run: baseline (no summaries "
        "loaded), ground-truth (every ground-truth file as user-specs), or llm (the "
        "LLM-generated summaries file as user-specs). Default: baseline.",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_run_taint)

    p = subparsers.add_parser(
        "run-find-interesting-methods",
        help="Run find-interesting-methods (produce then consume) against repo's built config",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.set_defaults(func=cmd_run_find_interesting_methods)

    p = subparsers.add_parser(
        "eval-checker-precision",
        help="RQ checker-precision: checker vs. ground truth vs. constructive",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--summaries",
        type=Path,
        help="Path to a single ground-truth summaries file that was checked "
        "(default: every file in experiment/ground-truth-summaries/<repo>/)",
    )
    p.add_argument("--check-report", required=True, type=Path)
    p.add_argument("--constructive-report", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_eval_checker_precision)

    p = subparsers.add_parser(
        "eval-checker-efficiency",
        help="RQ checker-efficiency: checker vs. constructive runtime",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--summaries",
        type=Path,
        help="Path to a single summaries file that was checked "
        "(default: every file in experiment/ground-truth-summaries/<repo>/)",
    )
    p.add_argument("--check-report", required=True, type=Path)
    p.add_argument("--constructive-report", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_eval_checker_efficiency)

    p = subparsers.add_parser(
        "eval-checker-ablation", help="RQ checker-ablation: sub-analysis usage counts"
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--summaries",
        type=Path,
        help="Path to a single summaries file that was checked "
        "(default: every file in experiment/ground-truth-summaries/<repo>/)",
    )
    p.add_argument("--check-report", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_eval_checker_ablation)

    p = subparsers.add_parser(
        "eval-llm-effectiveness",
        help="RQ llm-effectiveness: checker vs. LLM-generated summaries vs. constructive",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--summaries",
        required=True,
        type=Path,
        help="Path to the LLM-generated summaries file",
    )
    p.add_argument("--check-report", required=True, type=Path)
    p.add_argument("--constructive-report", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_eval_llm_effectiveness)

    p = subparsers.add_parser(
        "eval-workflow-efficiency",
        help="RQ workflow-efficiency: baseline vs. with-summaries taint analysis runtime, "
        "and summarization/checking overhead",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument("--summarization", required=True, type=Path)
    p.add_argument("--check-report", required=True, type=Path)
    p.add_argument("--taint-with-summaries", required=True, type=Path)
    p.add_argument("--taint-baseline", required=True, type=Path)
    p.add_argument("--constructive-report", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_eval_workflow_efficiency)

    p = subparsers.add_parser(
        "latex",
        help="(not yet implemented) Render a paper table from eval-* output files",
    )
    p.add_argument("--data", required=True, nargs="+", type=Path)
    p.set_defaults(func=_not_implemented("latex"))

    args = parser.parse_args()
    args.func(args)
    return 0


# ---------------------------------------------------------------------------
# Producer commands: invoke argot, write its raw JSON output.
# ---------------------------------------------------------------------------


def cmd_run_check(args: argparse.Namespace) -> None:
    _run_check_split(args.repo, args.variant, args.out)


def cmd_run_constructive(args: argparse.Namespace) -> None:
    methods_paths = [args.methods] if args.methods else _ground_truth_files(args.repo)
    _write_check_report(
        "run-constructive",
        args.repo,
        methods_paths,
        via="naive",
        out_path=args.out,
    )


def cmd_run_llm_summarization(args: argparse.Namespace) -> None:
    """Run argot-summarize (the LLM agent) against repo's to_summarize.json.

    The agent's file writes are sandboxed to --out-dir (experiment/llm-summaries/<repo>/),
    decoupled from the config file's location and the real repo checkout. Each batch (see
    --batch-size below) writes its own summaries-NNNN.yaml file rather than appending to a
    shared file, so one batch's mistake can't corrupt another's output. Once all batches are
    done, these are concatenated into a single summaries.yaml -- the file taint-llm.yaml/
    check-llm.yaml actually reference.
    """
    repo_dir(args.repo)  # sanity check that the repo checkout exists

    llm_dir = LLM_SUMMARIES_DIR / args.repo
    llm_dir.mkdir(parents=True, exist_ok=True)
    summaries_path = llm_dir / "summaries.yaml"

    # check-llm.yaml already points check-specs at summaries_path, so the agent can validate
    # its own output via argot_dataflow_check with no per-run config needed.
    config_path = GENERATED_CONFIGS_DIR / args.repo / "check-llm.yaml"
    if not config_path.exists():
        console.print(
            f"[red]{config_path} not found; run generate-configs --repo {args.repo} first[/red]"
        )
        sys.exit(1)
    config = yaml.safe_load(config_path.read_text())

    target_name = args.target or (config.get("targets") or [{}])[0].get("name")
    if not target_name:
        console.print(f"[red]run-llm-summarization: no target found in {config_path}[/red]")
        sys.exit(1)

    functions_path = INTERESTING_METHODS_DIR / args.repo / "to_summarize.json"
    if not functions_path.exists():
        console.print(
            f"[red]{functions_path} not found; run run-find-interesting-methods "
            f"--repo {args.repo} first[/red]"
        )
        sys.exit(1)

    stats_path = llm_dir / "summarize-stats.json"
    log_file = args.out.with_suffix(".log")
    cmd = [
        "argot-summarize",
        "--config",
        str(config_path.resolve()),
        "--target",
        target_name,
        "--functions",
        str(functions_path.resolve()),
        "--out-dir",
        str(llm_dir.resolve()),
        "--stats-json",
        str(stats_path),
        "--model",
        args.model,
    ]
    if args.inference_profile:
        cmd += ["--inference-profile", args.inference_profile]
    # Batched to avoid hitting the model's max-output-tokens limit on larger function lists.
    cmd += ["--batch-size", "1"]

    duration = _run_subprocess(
        cmd,
        cwd=llm_dir,
        log_file=log_file,
        label=f"run-llm-summarization ({args.repo})",
        timeout=None,
    )

    _consolidate_batch_summaries(llm_dir, summaries_path)

    stats = json.loads(stats_path.read_text()) if stats_path.exists() else None
    result = {
        "repo": args.repo,
        "duration_seconds": round(duration, 2),
        "stats": stats,
        "summaries_path": str(summaries_path),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2))
    console.print(f"[green]Wrote {args.out}[/green] ({duration:.1f}s)")
    console.print(f"[green]Generated summaries in {summaries_path}[/green]")


def _consolidate_batch_summaries(llm_dir: Path, summaries_path: Path) -> None:
    """Concatenate every summaries-*.yaml in llm_dir (one per batch, see
    cmd_run_llm_summarization) into a single summaries_path, the file taint-llm.yaml/
    check-llm.yaml actually reference."""
    combined: List[Any] = []
    for batch_path in sorted(llm_dir.glob("summaries-*.yaml")):
        batch = yaml.safe_load(batch_path.read_text()) or {}
        combined.extend(batch.get("dataflow-summaries") or [])
    summaries_path.write_text(yaml.safe_dump({"dataflow-summaries": combined}))


def cmd_run_taint(args: argparse.Namespace) -> None:
    """Run argot taint using the fixed generated-configs/<repo>/taint-<variant>.yaml."""
    repo_path = repo_dir(args.repo)
    config_path = GENERATED_CONFIGS_DIR / args.repo / f"taint-{args.variant}.yaml"
    if not config_path.exists():
        console.print(
            f"[red]{config_path} not found; run generate-configs --repo {args.repo} first[/red]"
        )
        sys.exit(1)

    (repo_path / "logs" / "argot").mkdir(parents=True, exist_ok=True)

    log_file = args.out.with_suffix(".log")
    label = f"run-taint ({args.repo}, {args.variant})"
    duration = _run_subprocess(
        ["argot", "taint", "-config", str(config_path.resolve())],
        cwd=repo_path,
        log_file=log_file,
        label=label,
        # exit code 2 is argot's generic "command returned an error" code, used both for
        # taint's expected "found taint flows" result and for a real crash/misconfiguration
        # -- tolerated here, disambiguated below by whether a report was actually written.
        tolerate_exit_codes=(2,),
    )

    report = _read_taint_report(log_file, repo_path)
    if report["report_path"] is None:
        console.print(f"[red]{label} failed; no report found, see {log_file}[/red]")
        sys.exit(1)
    report["duration_seconds"] = round(duration, 2)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    console.print(f"[green]Wrote {args.out}[/green] ({duration:.1f}s)")


def cmd_run_find_interesting_methods(args: argparse.Namespace) -> None:
    """Run find-interesting-methods produce then consume against repo's fixed
    generated-configs/<repo>/taint-baseline.yaml (the baseline, no-summaries config -- the
    same one used by `run-taint --variant baseline`).
    """
    # NOTE: find-interesting-methods is a separate Go binary (not installed anywhere). Unlike
    # project-root (resolved relative to the config file's own path, see analysis/config/config.go),
    # target file paths (e.g. "./main.go") are resolved by golang.org/x/tools/go/packages relative
    # to the process's cwd -- so the binary must run with cwd=repo_path, the same as argot itself.
    # That conflicts with needing `go run` (or `go build`) to execute from ar-go-tools' own module
    # (repo_path is a separate Go module, e.g. sample/badger, that find-interesting-methods' package
    # path is outside of) -- so a temp binary is built once from EXPERIMENT_DIR, then run separately
    # with cwd=repo_path.

    repo_path = repo_dir(args.repo)
    config_path = GENERATED_CONFIGS_DIR / args.repo / "taint-baseline.yaml"
    if not config_path.exists():
        console.print(
            f"[red]{config_path} not found; run generate-configs --repo {args.repo} first[/red]"
        )
        sys.exit(1)

    (repo_path / "logs" / "argot").mkdir(parents=True, exist_ok=True)

    out_dir = INTERESTING_METHODS_DIR / args.repo
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_out = out_dir / "raw.json"
    out = out_dir / "to_summarize.json"

    with tempfile.TemporaryDirectory() as tmp_bin_dir:
        bin_path = Path(tmp_bin_dir) / "find-interesting-methods"
        build_log = raw_out.with_suffix(".build.log")
        _run_subprocess(
            ["go", "build", "-o", str(bin_path), str(FIND_INTERESTING_METHODS_DIR)],
            cwd=EXPERIMENT_DIR,
            log_file=build_log,
            label=f"run-find-interesting-methods build ({args.repo})",
        )

        produce_log = raw_out.with_suffix(".log")
        _run_subprocess(
            [
                str(bin_path),
                "produce",
                "-config",
                str(config_path.resolve()),
                "-out",
                str(raw_out.resolve()),
            ],
            cwd=repo_path,
            log_file=produce_log,
            label=f"run-find-interesting-methods produce ({args.repo})",
        )

        consume_log = out.with_suffix(".log")
        duration = _run_subprocess(
            [
                str(bin_path),
                "consume",
                "-in",
                str(raw_out.resolve()),
                "-out",
                str(out.resolve()),
            ],
            cwd=repo_path,
            log_file=consume_log,
            label=f"run-find-interesting-methods consume ({args.repo})",
        )
    console.print(f"[green]Wrote {raw_out}[/green] and {out} ({duration:.1f}s)")


# ---------------------------------------------------------------------------
# eval-checker-* commands: pure analysis over already-produced check-report.json files.
# ---------------------------------------------------------------------------


def cmd_eval_checker_precision(args: argparse.Namespace) -> None:
    _run_eval_checker("precision", args, needs_constructive=True)


def cmd_eval_checker_efficiency(args: argparse.Namespace) -> None:
    _run_eval_checker("efficiency", args, needs_constructive=True)


def cmd_eval_checker_ablation(args: argparse.Namespace) -> None:
    _run_eval_checker("ablation", args, needs_constructive=False)


def cmd_eval_llm_effectiveness(args: argparse.Namespace) -> None:
    """RQ llm-effectiveness: same computation as eval-checker-precision (checker soundness +
    constructive excess-flow comparison), but against the LLM-generated summaries file
    (--summaries) rather than the RQ1 ground-truth corpus."""
    _run_eval_checker(
        "precision", args, needs_constructive=True, rq="llm-effectiveness"
    )


def cmd_eval_workflow_efficiency(args: argparse.Namespace) -> None:
    """RQ workflow-efficiency: is running the soundness checker + taint analysis with
    LLM-generated (checked-sound) models faster than the baseline taint analysis, and is the
    LLM-based summarization + checking faster than the constructive approach?"""
    summarization = json.loads(args.summarization.read_text())
    check_report = json.loads(args.check_report.read_text())
    taint_with = json.loads(args.taint_with_summaries.read_text())
    taint_baseline = json.loads(args.taint_baseline.read_text())
    constructive_report = json.loads(args.constructive_report.read_text())

    sum_duration = summarization.get("duration_seconds") or 0
    check_duration = _check_report_duration(check_report)
    with_duration = taint_with.get("duration_seconds") or 0
    baseline_duration = taint_baseline.get("duration_seconds") or 0
    constructive_duration = _check_report_duration(constructive_report)

    speedup = None
    if baseline_duration > 0 and with_duration > 0:
        speedup = round(baseline_duration / with_duration, 2)

    agentic_vs_constructive_speedup = None
    if constructive_duration > 0 and sum_duration > 0:
        agentic_vs_constructive_speedup = round(constructive_duration / sum_duration, 2)

    with_set = {
        (df["tag"], df["source"], df["sink"])
        for df in taint_with.get("dataflows") or []
    }
    baseline_set = {
        (df["tag"], df["source"], df["sink"])
        for df in taint_baseline.get("dataflows") or []
    }
    dataflows_match = with_set == baseline_set

    out = {
        "rq": "workflow-efficiency",
        "repo": args.repo,
        "summarization_seconds": sum_duration,
        "check_seconds": check_duration,
        "taint_with_summaries_seconds": with_duration,
        "taint_baseline_seconds": baseline_duration,
        "constructive_seconds": constructive_duration,
        "speedup_factor": speedup,
        "agentic_vs_constructive_speedup": agentic_vs_constructive_speedup,
        "dataflows_match": dataflows_match,
        "extra_dataflows_with_summaries": sorted(with_set - baseline_set),
        "missing_dataflows_with_summaries": sorted(baseline_set - with_set),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    console.print(f"[green]Wrote {args.out}[/green]")


def _check_report_duration(check_report: Dict[str, Any]) -> float:
    """Sum Elapsed (nanoseconds) across every result in a check-report.json, for the total
    checking/constructive time across all targets."""
    total_ns = 0
    for results in check_report.values():
        for r in results or []:
            total_ns += r.get("Elapsed") or 0
    return round(total_ns / 1e9, 2)


def _run_eval_checker(
    subcommand: str,
    args: argparse.Namespace,
    needs_constructive: bool,
    rq: Optional[str] = None,
) -> None:
    """Shell out to the eval-checker Go tool (experiment/eval-checker), which does the actual
    grouping/flow-count/excess-flow computation using analysis/summaries' own SummaryNode
    parsing and comparison logic, rather than re-implementing it here."""
    summaries_paths = (
        [args.summaries] if args.summaries else _ground_truth_files(args.repo)
    )
    cmd = [
        *(
            [EVAL_CHECKER_BIN]
            if EVAL_CHECKER_BIN
            else ["go", "run", str(EXPERIMENT_DIR / "eval-checker")]
        ),
        subcommand,
        "-repo",
        args.repo,
        "-check-report",
        str(args.check_report),
        "-out",
        str(args.out),
    ]
    for p in summaries_paths:
        cmd += ["-summaries", str(p)]
    if needs_constructive:
        cmd += ["-constructive-report", str(args.constructive_report)]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        console.print(result.stdout, end="")
    if result.returncode != 0:
        console.print(f"[red]eval-checker {subcommand} failed:[/red]\n{result.stderr}")
        sys.exit(1)
    if result.stderr:
        console.print(f"[yellow]{result.stderr}[/yellow]", end="")

    if rq is not None:
        data = json.loads(args.out.read_text())
        data["rq"] = rq
        args.out.write_text(json.dumps(data, indent=2))


def _not_implemented(name: str):
    def handler(_args: argparse.Namespace) -> None:
        console.print(f"[red]{name} is not yet implemented.[/red]")
        sys.exit(1)

    return handler


# ---------------------------------------------------------------------------
# Shared helpers for the producer commands (run-check, run-constructive).
# ---------------------------------------------------------------------------


def _ground_truth_files(repo: str) -> List[Path]:
    return sorted((GROUND_TRUTH_DIR / repo).glob("*.yaml"))


def _run_check_split(repo: str, variant: str, out_path: Path) -> None:
    """Implementation for run-check: runs `argot check` once per kind (functions, interface
    methods) against repo's pre-generated check-<variant>-split-{functions,interfaces}.yaml
    configs (see _generate_configs_for_repo / _split_entries_by_kind), and merges the resulting
    check-report.json's into out_path, tagged with which kind each result came from.

    Functions and interface methods are checked in separate, isolated `argot check` processes
    (like _write_check_report does per ground-truth file) so a memory-hungry interface can't
    compound with a function's retained state, and either can be diagnosed independently.
    A kind is skipped entirely if repo/variant has no entries of that kind (no config was
    generated for it -- see write_split_check_configs).
    """
    repo_path = repo_dir(repo)

    # argot check will not create its own reports-dir; it must already exist.
    (repo_path / "logs" / "argot").mkdir(parents=True, exist_ok=True)

    merged_report: Dict[str, Any] = {}
    total_duration = 0.0
    found_any_config = False
    for kind in ("functions", "interfaces"):
        config_path = (
            GENERATED_CONFIGS_DIR / repo / f"check-{variant}-split-{kind}.yaml"
        )
        if not config_path.exists():
            continue
        found_any_config = True

        part_out = out_path.with_suffix(f".{kind}.json")
        log_file = part_out.with_suffix(".log")
        label = f"run-check ({repo}, {variant}, {kind})"
        try:
            duration = _run_subprocess(
                ["argot", "check", "-config", str(config_path.resolve()), "-via", "all"],
                cwd=repo_path,
                log_file=log_file,
                label=label,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            console.print(
                f"[red]{label} failed ({e}); recording as a null result and continuing "
                "with the other kind.[/red]"
            )
            merged_report.setdefault(kind, None)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(merged_report, indent=2))
            continue

        report_path = None
        for line in log_file.read_text().splitlines():
            if "Full report written to" in line:
                report_path = Path(line.split("Full report written to", 1)[1].strip())
                break
        if report_path is None or not report_path.exists():
            console.print(f"[red]{label} did not produce a check-report.json; see {log_file}[/red]")
            sys.exit(1)

        total_duration += duration
        part_report = json.loads(report_path.read_text())
        any_null = False
        for target_name, results in part_report.items():
            # Tag each result with which kind it came from, so functions and interface
            # methods stay distinguishable after merging.
            tagged_target = f"{target_name}:{kind}"
            if results is None:
                merged_report.setdefault(tagged_target, None)
                any_null = True
                continue
            merged_report[tagged_target] = results
        if any_null:
            console.print(
                f"[red]{label} produced a null result for at least one target; keeping "
                f"{log_file} for diagnosis.[/red]"
            )
        else:
            log_file.unlink(missing_ok=True)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(merged_report, indent=2))

    if not found_any_config:
        console.print(
            f"[red]No check-{variant}-split-{{functions,interfaces}}.yaml found for {repo}; "
            f"run generate-configs --repo {repo}"
            + (
                " after run-llm-summarization has produced summaries.yaml"
                if variant == "llm"
                else ""
            )
            + ".[/red]"
        )
        sys.exit(1)

    console.print(f"[green]Wrote {out_path}[/green] ({total_duration:.1f}s)")


def _write_check_report(
    cmd_name: str,
    repo: str,
    summaries_or_methods_paths: List[Path],
    via: str,
    out_path: Path,
) -> None:
    """Shared implementation for run-constructive: runs `argot check` once per path in
    summaries_or_methods_paths, and merges the resulting check-report.json's into out_path.

    Each path is checked in its own argot check process (rather than combining them into one
    check-specs list) so that one memory-hungry interface can't compound with another path's
    retained state, and a runaway invocation can be killed/retried independently.
    """
    repo_path = repo_dir(repo)

    merged_report: Dict[str, Any] = {}
    total_duration = 0.0
    for part_path in summaries_or_methods_paths:
        part_out = out_path.with_suffix(f".{part_path.stem}.json")
        try:
            duration = _run_one_check(
                cmd_name, repo, repo_path, part_path, via, part_out
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            console.print(
                f"[red]{cmd_name} ({repo}, {part_path.stem}) failed ({e}); "
                "recording as a null result and continuing with remaining parts.[/red]"
            )
            merged_report.setdefault(part_path.stem, None)
            # Persist what's been collected so far before moving on, so a subsequent
            # part's crash (or the whole process being killed) doesn't lose this one.
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(merged_report, indent=2))
            continue
        total_duration += duration
        part_report = json.loads(part_out.read_text())
        any_null = False
        for target_name, results in part_report.items():
            if results is None:
                merged_report.setdefault(target_name, None)
                any_null = True
                continue
            existing = merged_report.get(target_name)
            merged_report[target_name] = (existing or []) + results
        part_out.unlink()
        if any_null:
            console.print(
                f"[red]{cmd_name} ({repo}, {part_path.stem}) produced a null result for at "
                f"least one target; keeping {part_out.with_suffix('.log')} for diagnosis.[/red]"
            )
        else:
            part_out.with_suffix(".log").unlink(missing_ok=True)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(merged_report, indent=2))

    console.print(f"[green]Wrote {out_path}[/green] ({total_duration:.1f}s)")


def _run_one_check(
    cmd_name: str,
    repo: str,
    repo_path: Path,
    summaries_or_methods_path: Path,
    via: str,
    out_path: Path,
) -> float:
    """Run a single `argot check` invocation against summaries_or_methods_path and write its
    check-report.json verbatim to out_path. Returns the elapsed time in seconds.

    summaries_or_methods_path must be one of repo's standard ground-truth files -- the matching
    pre-generated generated-configs/<repo>/check-ground-truth-<stem>.yaml is used directly. No
    config is assembled at run time; an arbitrary/unrecognized path fails fast instead.
    """
    config_path = (
        GENERATED_CONFIGS_DIR
        / repo
        / f"check-ground-truth-{summaries_or_methods_path.stem}.yaml"
    )
    if (
        summaries_or_methods_path not in _ground_truth_files(repo)
        or not config_path.exists()
    ):
        console.print(
            f"[red]{summaries_or_methods_path} is not one of {repo}'s ground-truth files "
            f"with a generated config ({config_path} not found). Run generate-configs "
            f"--repo {repo}, or pass one of the files under "
            f"{GROUND_TRUTH_DIR / repo}.[/red]"
        )
        sys.exit(1)

    # argot check will not create its own reports-dir; it must already exist.
    (repo_path / "logs" / "argot").mkdir(parents=True, exist_ok=True)

    log_file = out_path.with_suffix(".log")
    label = f"{cmd_name} ({repo}, {summaries_or_methods_path.stem})"
    duration = _run_subprocess(
        ["argot", "check", "-config", str(config_path.resolve()), "-via", via],
        cwd=repo_path,
        log_file=log_file,
        label=label,
    )

    report_path = None
    content = log_file.read_text()
    for line in content.splitlines():
        if "Full report written to" in line:
            report_path = Path(line.split("Full report written to", 1)[1].strip())
            break

    if report_path is None or not report_path.exists():
        console.print(
            f"[red]{label} did not produce a check-report.json; see {log_file}[/red]"
        )
        sys.exit(1)

    out_path.write_text(report_path.read_text())
    return duration


def _base_config(repo: str) -> Dict[str, Any]:
    """Build the shared template plus repo's argot-configs/<repo>/target.yaml (single build
    target) merged in -- everything every generated config needs, regardless of task. Callers
    add task-specific pieces on top (taint-tracking for taint configs, check-specs for check
    configs, etc.) -- see _generate_configs_for_repo.
    """
    config: Dict[str, Any] = {
        "dataflow-problems": {
            "summarize-on-demand": True,
            "check-ignores-unsound": True,
            "intra-timeout-ms": 60000,  # 1 minute per-function cap
        },
        "options": {
            "project-root": "./",
            "reports-dir": "logs/argot",
            "log-level": 3,
            "report-paths": True,
            "analysis-options": {"unsafe-max-depth": 35},
        },
    }

    target = yaml.safe_load((ARGOT_CONFIGS_DIR / repo / "target.yaml").read_text())
    assert isinstance(target, dict)  # There must only be a single target per repo.
    config["targets"] = [target]

    if not config.get("targets"):
        console.print(f"[red]{repo}: built config has no target[/red]")
        sys.exit(1)
    return config


def _taint_specs(repo: str) -> List[Dict[str, Any]]:
    """Load repo's argot-configs/<repo>/taint-specs.yaml (taint-tracking problems) -- only
    needed by taint-analysis configs (taint-baseline/ground-truth/llm and
    find-interesting-methods), not by check configs, which never reference taint-tracking at
    all (see cmd/argot/check/check.go -- it only reads CheckSpecs)."""
    taint_specs = yaml.safe_load(
        (ARGOT_CONFIGS_DIR / repo / "taint-specs.yaml").read_text()
    )
    if not taint_specs:
        console.print(f"[red]{repo}: built config has no taint-tracking problems[/red]")
        sys.exit(1)
    return taint_specs


def cmd_generate_configs(args: argparse.Namespace) -> None:
    repos = [args.repo] if args.repo else sorted(REPOS)
    for repo in repos:
        paths = _generate_configs_for_repo(repo)
        console.print(f"[green]Generated {len(paths)} config(s) for {repo}[/green]")


def _split_entries_by_kind(
    entries: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split a flat list of raw dataflow-summaries entries (as loaded from a summaries YAML's
    "dataflow-summaries" key) into (functions, interfaces), using the same discriminator as
    analysis/summaries' rawDataflowSummary.compile(): an entry is an interface-method summary
    iff its "interface" key is set (non-empty); otherwise it's a function/receiver-method
    summary. See ar-go-tools' analysis/summaries/frontend.go.
    """
    functions: List[Dict[str, Any]] = []
    interfaces: List[Dict[str, Any]] = []
    for entry in entries:
        if entry.get("interface"):
            interfaces.append(entry)
        else:
            functions.append(entry)
    return functions, interfaces


def _load_all_entries(paths: List[Path]) -> List[Dict[str, Any]]:
    """Load and concatenate the "dataflow-summaries" lists of every YAML file in paths."""
    entries: List[Dict[str, Any]] = []
    for p in paths:
        data = yaml.safe_load(p.read_text()) or {}
        entries.extend(data.get("dataflow-summaries") or [])
    return entries


def _generate_configs_for_repo(repo: str) -> List[Path]:
    """Write the fixed set of read-only argot-config.yaml files for repo to
    generated-configs/<repo>/, replacing whatever was there before. Every consumer (run-taint,
    run-check, run-find-interesting-methods, run-llm-summarization) reads one of these paths
    directly instead of assembling a config (in a temp file or otherwise) at run time.

    Each config includes only what its task actually needs: taint configs get taint-tracking
    and no check-specs/user-specs beyond what the variant calls for; check configs get
    check-specs and no taint-tracking at all (the soundness checker never reads it).

    The kinds of task, and which of these files serves each:
      - baseline taint analysis (also used by find-interesting-methods): taint-baseline.yaml
      - taint analysis with ground-truth summaries loaded: taint-ground-truth.yaml
      - taint analysis with LLM-generated summaries loaded: taint-llm.yaml
      - checking soundness of each ground-truth summaries file: check-ground-truth-<stem>.yaml
        (one per file in ground-truth-summaries/<repo>/, kept separate rather than combined
        into one check-specs list, so each file's `argot check` run is isolated -- see
        _run_one_check)
      - checking soundness of the LLM-generated summaries file: check-llm.yaml
      - checking soundness of ground-truth/LLM summaries split by kind (function vs. interface
        method), used by run-check --variant {ground-truth,llm}: every ground-truth file's (or
        the LLM file's) dataflow-summaries entries are pooled, then partitioned into functions
        and interface methods (see _split_entries_by_kind), and each half is materialized as
        its own data file (_split-ground-truth-functions.yaml, _split-ground-truth-
        interfaces.yaml, _split-llm-functions.yaml, _split-llm-interfaces.yaml) with a matching
        check-ground-truth-split-{functions,interfaces}.yaml / check-llm-split-
        {functions,interfaces}.yaml config, so functions and interface methods are always
        checked in separate, isolated `argot check` invocations.

    user-specs/check-specs entries are resolved relative to project-root (the repo checkout),
    not to the generated config file's own location -- see argot/analysis/config/config.go -- so
    paths back to experiment/ground-truth-summaries or experiment/llm-summaries are computed
    relative to repo_dir(repo) regardless of where the generated config file itself lives.
    """
    repo_path = repo_dir(repo)
    out_dir = GENERATED_CONFIGS_DIR / repo
    # Generated files are overwritten in place rather than the directory being cleared, so
    # hand-written configs alongside them survive.
    out_dir.mkdir(parents=True, exist_ok=True)

    # Names of every file this run writes, including the _split-* data files that `written` omits.
    # Anything else in out_dir is either hand-written or left over from a run whose inputs differed,
    # and is reported at the end so a stale config is not mistaken for a current one.
    produced: Set[str] = set()

    # NOTE: project-root is resolved relative to the config file's location, so it must point from
    # out_dir back to repo_path instead.
    project_root = os.path.relpath(repo_path.resolve(), start=out_dir.resolve())

    def write_taint_config(name: str, user_specs: Optional[List[str]] = None) -> Path:
        config = _base_config(repo)
        config["options"]["project-root"] = project_root
        config["dataflow-problems"]["taint-tracking"] = _taint_specs(repo)
        # Analyze every function field-sensitively. Only the taint analysis needs this: `argot check`
        # takes its access path length from the summary being checked and ignores this setting.
        config["dataflow-problems"]["field-sensitive-funcs"] = [".*"]
        if user_specs:
            config["dataflow-problems"]["user-specs"] = user_specs
        path = out_dir / name
        path.write_text(yaml.safe_dump(config))
        produced.add(path.name)
        return path

    def write_check_config(name: str, check_specs: List[str]) -> Path:
        config = _base_config(repo)
        config["options"]["project-root"] = project_root
        config["dataflow-problems"]["check-specs"] = check_specs
        path = out_dir / name
        path.write_text(yaml.safe_dump(config))
        produced.add(path.name)
        return path

    def rel_to_repo(p: Path) -> str:
        return os.path.relpath(p.resolve(), start=repo_path.resolve())

    written = []

    # Baseline: no user-specs.
    written.append(write_taint_config("taint-baseline.yaml"))

    # Taint analysis with every ground-truth file combined into one user-specs list.
    ground_truth_paths = _ground_truth_files(repo)
    written.append(
        write_taint_config(
            "taint-ground-truth.yaml",
            user_specs=[rel_to_repo(p) for p in ground_truth_paths],
        )
    )

    # Taint analysis with the LLM-generated summaries file as user-specs.
    llm_summaries_path = LLM_SUMMARIES_DIR / repo / "summaries.yaml"
    written.append(
        write_taint_config(
            "taint-llm.yaml", user_specs=[rel_to_repo(llm_summaries_path)]
        )
    )

    # One soundness-check config per ground-truth file, isolated from each other. No
    # taint-tracking at all -- argot check never reads it (see cmd/argot/check/check.go).
    for gt_path in ground_truth_paths:
        written.append(
            write_check_config(
                f"check-ground-truth-{gt_path.stem}.yaml",
                check_specs=[rel_to_repo(gt_path)],
            )
        )

    # Soundness-check config for the LLM-generated summaries file.
    written.append(
        write_check_config(
            "check-llm.yaml", check_specs=[rel_to_repo(llm_summaries_path)]
        )
    )

    def write_split_check_configs(prefix: str, data_paths: List[Path]) -> None:
        """Pool every file in data_paths, split by kind (see _split_entries_by_kind), and
        write one materialized data file + matching check config per non-empty kind, named
        _split-<prefix>-{functions,interfaces}.yaml and check-<prefix>-split-
        {functions,interfaces}.yaml. Skips a kind entirely if it has no entries, so run-check
        doesn't have to special-case an empty check-specs list. Skips entirely if any of
        data_paths doesn't exist yet (e.g. the LLM summaries file, generated later by
        run-llm-summarization -- callers must re-run generate-configs afterward)."""
        if not all(p.exists() for p in data_paths):
            return
        entries = _load_all_entries(data_paths)
        functions, interfaces = _split_entries_by_kind(entries)
        for kind, kind_entries in (("functions", functions), ("interfaces", interfaces)):
            if not kind_entries:
                continue
            data_path = out_dir / f"_split-{prefix}-{kind}.yaml"
            data_path.write_text(
                yaml.safe_dump({"dataflow-summaries": kind_entries})
            )
            produced.add(data_path.name)
            written.append(
                write_check_config(
                    f"check-{prefix}-split-{kind}.yaml",
                    check_specs=[rel_to_repo(data_path)],
                )
            )

    # Ground-truth and LLM summaries, pooled and split by kind (function vs. interface
    # method) rather than by source file -- see run-check --variant {ground-truth,llm}.
    write_split_check_configs("ground-truth", ground_truth_paths)
    write_split_check_configs("llm", [llm_summaries_path])

    extra = sorted(
        p.name for p in out_dir.iterdir() if p.is_file() and p.name not in produced
    )
    if extra:
        console.print(
            f"[yellow]{repo}: {len(extra)} file(s) in {out_dir} were not written by this run "
            f"(hand-written, or stale from a previous run): {', '.join(extra)}[/yellow]"
        )

    return written


def _read_taint_report(log_file: Path, repo_path: Path) -> Dict[str, Any]:
    """Parse an `argot taint` run's log for its "Wrote final report in <path>" line, then read
    that overall-report-*.json and every per-flow report file it references, returning a dict
    with a flat list of {tag, source, sink} dataflows found."""
    content = log_file.read_text() if log_file.exists() else ""
    m = re.search(r"Wrote final report in (\S+)", content)
    if not m:
        console.print(f"[red]run-taint: no final report path found in {log_file}[/red]")
        return {"dataflows": [], "count_by_severity": {}, "report_path": None}

    report_path = Path(m.group(1))
    if not report_path.is_absolute():
        report_path = repo_path / report_path
    if not report_path.exists():
        console.print(f"[red]run-taint: report file not found: {report_path}[/red]")
        return {"dataflows": [], "count_by_severity": {}, "report_path": None}

    overall = json.loads(report_path.read_text())
    dataflows = []
    for tag, group in (overall.get("Reports") or {}).items():
        for detail_path in group.get("Details") or []:
            p = Path(detail_path)
            if not p.is_absolute():
                p = repo_path / p
            if not p.exists():
                continue
            flow = json.loads(p.read_text())
            dataflows.append(
                {
                    "tag": tag,
                    "source": (flow.get("Source") or {}).get("Position", ""),
                    "sink": (flow.get("Sink") or {}).get("Position", ""),
                }
            )

    return {
        "dataflows": dataflows,
        "count_by_severity": overall.get("CountBySeverity") or {},
        "report_path": str(report_path),
    }


def _run_subprocess(
    cmd: List[str],
    cwd: Path,
    log_file: Path,
    label: str,
    timeout: Optional[int] = None,
    tolerate_exit_codes: Tuple[int, ...] = (),
) -> float:
    """Run a subprocess, logging its output to log_file. Returns the duration in seconds.

    Raises subprocess.TimeoutExpired if timeout elapses, CalledProcessError on nonzero exit
    unless the exit code is in tolerate_exit_codes (e.g. argot taint's exit code 1 for "found
    taint flows", which is an expected, meaningful result, not a crash). On failure, the last
    lines of log_file are also printed, so callers don't need to open the file themselves just
    to see why a command failed.
    """
    console.print(f"[dim]Running {label}...[/dim]")
    start_time = time.time()
    with open(log_file, "w") as f:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    finally:
        duration = time.time() - start_time

    if proc.returncode != 0 and proc.returncode not in tolerate_exit_codes:
        console.print(f"[red]{label} failed (exit {proc.returncode}); last lines of {log_file}:[/red]")
        tail = log_file.read_text().splitlines()[-20:]
        console.print("[red]" + "\n".join(tail) + "[/red]")
        raise subprocess.CalledProcessError(proc.returncode, cmd)

    console.print(f"  [dim]{label}:[/dim] {duration:.1f}s")
    return duration


# ---------------------------------------------------------------------------
# Generic low-level utilities.
# ---------------------------------------------------------------------------


def repo_dir(repo: str) -> Path:
    d = REPOS_BASE_DIR / repo
    if not d.exists():
        console.print(f"[red]Repository directory not found: {d}[/red]")
        sys.exit(1)
    return d


if __name__ == "__main__":
    sys.exit(main())
