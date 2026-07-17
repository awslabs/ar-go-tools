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
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from rich.console import Console

console = Console()

EXPERIMENT_DIR = Path(__file__).parent
REPOS_BASE_DIR = EXPERIMENT_DIR.parent / "payload" / "public-repos-checks"
GROUND_TRUTH_DIR = EXPERIMENT_DIR / "ground-truth"


@dataclass(frozen=True)
class Target:
    """One argot-config.yaml build target."""

    name: str
    files: List[str]


@dataclass(frozen=True)
class RepoInfo:
    """Everything needed to check out a target repo at a pinned commit and build an
    argot-config.yaml for it. url/commit are pinned for reproducibility (see Dockerfile)."""

    url: str
    commit: str
    targets: List[Target]


# The 5 repos used for the checker-precision (RQ1) ground-truth evaluation. Each repo's
# argot-config.yaml is generated from _build_config below rather than checked into the repo,
# since it's almost entirely boilerplate -- the only real per-repo variation is the build
# targets.
REPOS: Dict[str, RepoInfo] = {
    "amazon-ssm-agent": RepoInfo(
        url="https://github.com/aws/amazon-ssm-agent.git",
        commit="ef5df636f7035bb1e3e325fab519379715678033",
        targets=[
            Target(
                name="amazon-ssm-agent-unix",
                files=["core/agent.go", "core/agent_unix.go", "core/agent_parser.go"],
            ),
        ],
    ),
    "badger": RepoInfo(
        url="https://github.com/dgraph-io/badger.git",
        commit="a700dc3b6332e2351674f34f841233541568f782",
        targets=[Target(name="badger-cli", files=["./badger/"])],
    ),
    "govatar": RepoInfo(
        url="https://github.com/o1egl/govatar.git",
        commit="31618c34a7ae828c61629e022b1654e4ec552628",
        targets=[Target(name="govatar-cli", files=["./govatar"])],
    ),
    "prometheus": RepoInfo(
        url="https://github.com/prometheus/client_golang.git",
        commit="7ba246a648ca4e294ca008d95b6fcc8df2f9c255",
        targets=[
            Target(name="example-simple", files=["./examples/simple/main.go"]),
            Target(name="example-random", files=["./examples/random/main.go"]),
            Target(name="gocollector", files=["./examples/gocollector/main.go"]),
            Target(name="middleware", files=["./examples/middleware/main.go"]),
        ],
    ),
    "sample": RepoInfo(
        url="",  # local-only sample program, tracked directly in this repo; not cloned
        commit="",
        targets=[Target(name="sample-main", files=["./main.go"])],
    ),
}


def _ground_truth_files(repo: str) -> List[Path]:
    return sorted((GROUND_TRUTH_DIR / repo).glob("*.yaml"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p = subparsers.add_parser(
        "run-check", help="Run the soundness checker against a summaries file"
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--summaries",
        type=Path,
        help="Path to a single summaries YAML to check "
        "(default: every file in experiment/ground-truth/<repo>/)",
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
        "(default: every file in experiment/ground-truth/<repo>/)",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_run_constructive)

    p = subparsers.add_parser(
        "generate", help="(not yet implemented) Run LLM-based summary generation"
    )
    p.add_argument("--repo", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_not_implemented("generate"))

    p = subparsers.add_parser(
        "run-taint-baseline",
        help="(not yet implemented) Run the taint analysis without any summaries",
    )
    p.add_argument("--repo", required=True)
    p.add_argument("--taint-problems", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_not_implemented("run-taint-baseline"))

    p = subparsers.add_parser(
        "run-taint-models",
        help="(not yet implemented) Run the taint analysis with checked-sound summaries",
    )
    p.add_argument("--repo", required=True)
    p.add_argument("--taint-problems", required=True)
    p.add_argument("--summaries", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_not_implemented("run-taint-models"))

    p = subparsers.add_parser(
        "eval-checker-precision",
        help="RQ checker-precision: checker vs. ground truth vs. constructive",
    )
    p.add_argument("--repo", required=True, choices=sorted(REPOS))
    p.add_argument(
        "--summaries",
        type=Path,
        help="Path to a single ground-truth summaries file that was checked "
        "(default: every file in experiment/ground-truth/<repo>/)",
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
        "(default: every file in experiment/ground-truth/<repo>/)",
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
        "(default: every file in experiment/ground-truth/<repo>/)",
    )
    p.add_argument("--check-report", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_eval_checker_ablation)

    p = subparsers.add_parser(
        "eval-llm-effectiveness", help="(not yet implemented) RQ llm-effectiveness"
    )
    p.add_argument("--repo", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_not_implemented("eval-llm-effectiveness"))

    p = subparsers.add_parser(
        "eval-workflow-efficiency", help="(not yet implemented) RQ workflow-efficiency"
    )
    p.add_argument("--repo", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_not_implemented("eval-workflow-efficiency"))

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
    summaries_paths = (
        [args.summaries] if args.summaries else _ground_truth_files(args.repo)
    )
    _write_check_report(
        "run-check",
        args.repo,
        summaries_paths,
        via="all",
        extra_config={},
        out_path=args.out,
    )


def cmd_run_constructive(args: argparse.Namespace) -> None:
    methods_paths = [args.methods] if args.methods else _ground_truth_files(args.repo)
    _write_check_report(
        "run-constructive",
        args.repo,
        methods_paths,
        via="naive",
        extra_config={},
        out_path=args.out,
    )


# ---------------------------------------------------------------------------
# eval-checker-* commands: pure analysis over already-produced check-report.json files.
# ---------------------------------------------------------------------------


def cmd_eval_checker_precision(args: argparse.Namespace) -> None:
    _run_eval_checker("precision", args, needs_constructive=True)


def cmd_eval_checker_efficiency(args: argparse.Namespace) -> None:
    _run_eval_checker("efficiency", args, needs_constructive=True)


def cmd_eval_checker_ablation(args: argparse.Namespace) -> None:
    _run_eval_checker("ablation", args, needs_constructive=False)


def _run_eval_checker(subcommand: str, args: argparse.Namespace, needs_constructive: bool) -> None:
    """Shell out to the eval-checker Go tool (experiment/eval-checker), which does the actual
    grouping/flow-count/excess-flow computation using analysis/summaries' own SummaryNode
    parsing and comparison logic, rather than re-implementing it here."""
    summaries_paths = (
        [args.summaries] if args.summaries else _ground_truth_files(args.repo)
    )
    cmd = [
        "go", "run", str(EXPERIMENT_DIR / "eval-checker"), subcommand,
        "-repo", args.repo,
        "-check-report", str(args.check_report),
        "-out", str(args.out),
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


def _not_implemented(name: str):
    def handler(_args: argparse.Namespace) -> None:
        console.print(f"[red]{name} is not yet implemented.[/red]")
        sys.exit(1)

    return handler


# ---------------------------------------------------------------------------
# Shared helpers for the producer commands (run-check, run-constructive).
# ---------------------------------------------------------------------------


def _write_check_report(
    cmd_name: str,
    repo: str,
    summaries_or_methods_paths: List[Path],
    via: str,
    extra_config: Dict[str, Any],
    out_path: Path,
) -> None:
    """Shared implementation for run-check and run-constructive: runs `argot check` once per
    path in summaries_or_methods_paths, and merges the resulting check-report.json's into
    out_path.

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
                cmd_name, repo, repo_path, part_path, via, extra_config, part_out
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
    extra_config: Dict[str, Any],
    out_path: Path,
) -> float:
    """Run a single `argot check` invocation against summaries_or_methods_path and write its
    check-report.json verbatim to out_path. Returns the elapsed time in seconds."""
    config = _build_config(repo)
    config["dataflow-problems"]["user-specs"] = []
    config["dataflow-problems"]["check-specs"] = [
        os.path.relpath(str(summaries_or_methods_path.resolve()), start=repo_path)
    ]
    config["dataflow-problems"].update(extra_config)

    # argot check will not create its own reports-dir; it must already exist.
    (repo_path / config["options"]["reports-dir"]).mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".yaml",
        dir=repo_path,
        prefix=".tmp-argot-config-",
        delete=False,
    ) as tmp:
        yaml.safe_dump(config, tmp)
        tmp_config_path = Path(tmp.name)

    log_file = out_path.with_suffix(".log")
    label = f"{cmd_name} ({repo}, {summaries_or_methods_path.stem})"
    try:
        duration = _run_subprocess(
            ["argot", "check", "-config", tmp_config_path.name, "-via", via],
            cwd=repo_path,
            log_file=log_file,
            label=label,
        )
    finally:
        tmp_config_path.unlink(missing_ok=True)

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


def _build_config(repo: str) -> Dict[str, Any]:
    """Build a minimal argot-config.yaml for repo from the shared template. The only
    per-repo variation is the build targets; check-specs/user-specs are always overridden by
    _write_check_report before this is used."""
    info = REPOS[repo]
    return {
        "dataflow-problems": {
            "summarize-on-demand": True,
            "check-ignores-unsound": True,
            "field-sensitive-funcs": [".*"],
        },
        "options": {
            "project-root": "./",
            "reports-dir": "logs/argot",
            "log-level": 3,
            "report-paths": True,
            "analysis-options": {"unsafe-max-depth": 30, "max-alarms": 30},
        },
        "targets": [{"name": t.name, "files": t.files} for t in info.targets],
    }


def _run_subprocess(
    cmd: List[str], cwd: Path, log_file: Path, label: str, timeout: Optional[int] = None
) -> float:
    """Run a subprocess, logging its output to log_file. Returns the duration in seconds.

    Raises subprocess.TimeoutExpired if timeout elapses, CalledProcessError on nonzero exit.
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

    if proc.returncode != 0:
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
