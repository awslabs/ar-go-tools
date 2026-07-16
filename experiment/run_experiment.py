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
class RepoInfo:
    """Everything needed to check out a target repo at a pinned commit and build an
    argot-config.yaml for it. url/commit are pinned for reproducibility (see Dockerfile)."""

    url: str
    commit: str
    target_name: str
    target_files: List[str]


# The 5 repos used for the checker-precision (RQ1) ground-truth evaluation. Each repo's
# argot-config.yaml is generated from _build_config below rather than checked into the repo,
# since it's almost entirely boilerplate -- the only real per-repo variation is the build
# target. The taint-tracking entry in the generated config is a placeholder: argot check
# requires every target to be referenced by a taint-tracking/slicing problem to be selected,
# even though the taint spec's actual sources/sinks are irrelevant to `check`.
REPOS: Dict[str, RepoInfo] = {
    "amazon-ssm-agent": RepoInfo(
        url="https://github.com/aws/amazon-ssm-agent.git",
        commit="ef5df636f7035bb1e3e325fab519379715678033",
        target_name="amazon-ssm-agent-unix",
        target_files=["core/agent.go", "core/agent_unix.go", "core/agent_parser.go"],
    ),
    "badger": RepoInfo(
        url="https://github.com/dgraph-io/badger.git",
        commit="a700dc3b6332e2351674f34f841233541568f782",
        target_name="badger-cli",
        target_files=["./badger/"],
    ),
    "govatar": RepoInfo(
        url="https://github.com/o1egl/govatar.git",
        commit="31618c34a7ae828c61629e022b1654e4ec552628",
        target_name="govatar-cli",
        target_files=["./govatar"],
    ),
    "prometheus": RepoInfo(
        url="https://github.com/prometheus/client_golang.git",
        commit="7ba246a648ca4e294ca008d95b6fcc8df2f9c255",
        target_name="prometheus-core",
        target_files=["./prometheus"],
    ),
    "sample": RepoInfo(
        url="",  # local-only sample program, tracked directly in this repo; not cloned
        commit="",
        target_name="sample-main",
        target_files=["./main.go"],
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
    check_report = json.loads(Path(args.check_report).read_text())
    constructive_report = json.loads(Path(args.constructive_report).read_text())
    summaries_paths = (
        [args.summaries] if args.summaries else _ground_truth_files(args.repo)
    )
    targets = _build_targets(check_report, summaries_paths, constructive_report)

    for t in targets:
        for r in t["results"]:
            r.pop("checker_seconds", None)
            r.pop("constructive_seconds", None)

    out = {"rq": "checker-precision", "repo": args.repo, "targets": targets}
    Path(args.out).write_text(json.dumps(out, indent=2))
    console.print(f"[green]Wrote {args.out}[/green]")


def cmd_eval_checker_efficiency(args: argparse.Namespace) -> None:
    check_report = json.loads(Path(args.check_report).read_text())
    constructive_report = json.loads(Path(args.constructive_report).read_text())
    summaries_paths = (
        [args.summaries] if args.summaries else _ground_truth_files(args.repo)
    )
    targets = _build_targets(check_report, summaries_paths, constructive_report)

    for t in targets:
        for r in t["results"]:
            r.pop("checker_soundness", None)
            r.pop("checker_method", None)
            r.pop("ground_truth_flow_count", None)
            r.pop("constructive_flow_count", None)
            r.pop("constructive_excess_flow_count", None)

    out = {"rq": "checker-efficiency", "repo": args.repo, "targets": targets}
    Path(args.out).write_text(json.dumps(out, indent=2))
    console.print(f"[green]Wrote {args.out}[/green]")


def cmd_eval_checker_ablation(args: argparse.Namespace) -> None:
    check_report = json.loads(Path(args.check_report).read_text())
    summaries_paths = (
        [args.summaries] if args.summaries else _ground_truth_files(args.repo)
    )
    targets = _build_targets(check_report, summaries_paths)

    for t in targets:
        for r in t["results"]:
            for key in list(r.keys()):
                if key not in ("name", "checker_method"):
                    del r[key]

    out = {"rq": "checker-ablation", "repo": args.repo, "targets": targets}
    Path(args.out).write_text(json.dumps(out, indent=2))
    console.print(f"[green]Wrote {args.out}[/green]")


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
        for target_name, results in part_report.items():
            if results is None:
                merged_report.setdefault(target_name, None)
                continue
            existing = merged_report.get(target_name)
            merged_report[target_name] = (existing or []) + results
        part_out.unlink()
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
    per-repo variation is the build target; check-specs/user-specs are always overridden by
    _write_check_report before this is used, and the taint-tracking entry is a placeholder
    that exists solely to make the target selectable by `argot check` (see REPOS)."""
    info = REPOS[repo]
    return {
        "dataflow-problems": {
            "summarize-on-demand": True,
            "check-ignores-unsound": True,
            "field-sensitive-funcs": [".*"],
            "taint-tracking": [
                {
                    "tag": "target-selection-placeholder",
                    "description": "Placeholder taint-tracking problem so that the build "
                    "target below is selected by `argot check`; not used for RQ1.",
                    "targets": [info.target_name],
                    "sources": [{"method": "^main$", "package": "main"}],
                    "sinks": [{"method": "^main$", "package": "main"}],
                }
            ],
        },
        "options": {
            "project-root": "./",
            "reports-dir": "logs/argot",
            "log-level": 3,
            "report-paths": True,
            "analysis-options": {"unsafe-max-depth": 30, "max-alarms": 30},
        },
        "targets": [{"name": info.target_name, "files": info.target_files}],
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
# Shared helpers for the eval-checker-* commands.
# ---------------------------------------------------------------------------


def _build_targets(
    check_report: Dict[str, Any],
    summaries_paths: List[Path],
    constructive_report: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build the targets/kind/results grouping shared by eval-checker-* commands.

    summaries_paths are the summaries files that were checked (ground truth, for
    eval-checker-precision/efficiency/ablation): each entry becomes one target, grouped by
    SummaryName (see _group_by_summary_name) -- an interface entry's target has one result per
    concrete implementation, a plain function/method's target has exactly one result.
    """
    entries = _load_summary_entries(summaries_paths)
    check_by_summary = _group_by_summary_name(check_report)
    constructive_by_func = {}
    if constructive_report:
        for target_name, results in constructive_report.items():
            if results is None:
                console.print(
                    f"[red]Warning: target {target_name!r} has no results in the "
                    "constructive report; see the .log file.[/red]"
                )
                continue
            for r in results:
                constructive_by_func.setdefault(r.get("Func", ""), []).append(r)

    targets = []
    for entry in entries:
        kind = "interface" if "interface" in entry else "function"
        summary_name = _summary_entry_name(entry)

        check_results = check_by_summary.get(summary_name, [])
        results = []
        for check_result in check_results:
            func_name = check_result.get("Func", "")
            constructive_matches = constructive_by_func.get(func_name, [])
            results.append(
                _merge_result(
                    check_result,
                    constructive_matches[0] if constructive_matches else None,
                )
            )

        targets.append({"summary_name": summary_name, "kind": kind, "results": results})

    return targets


def _merge_result(
    check_result: Dict[str, Any], constructive_result: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    want = check_result.get("Want") or {}
    merged = {
        "name": check_result.get("Func", ""),
        "checker_soundness": check_result.get("Soundness", ""),
        "checker_method": check_result.get("Method", ""),
        "checker_seconds": (check_result.get("Elapsed") or 0) / 1e9,
        "ground_truth_flow_count": _flow_count(want),
    }
    if constructive_result is not None:
        got = constructive_result.get("Got") or {}
        merged["constructive_flow_count"] = _flow_count(got)
        merged["constructive_excess_flow_count"] = _excess_flow_count(want, got)
        merged["constructive_seconds"] = (constructive_result.get("Elapsed") or 0) / 1e9
    return merged


def _group_by_summary_name(
    report: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Group a check-report.json's flat per-target result lists by SummaryName (the
    top-level summary entry each result was checked against). For an interface method, every
    concrete implementation's result shares the same SummaryName (the interface method's own
    name); for a plain function, SummaryName equals Func."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for target_name, results in report.items():
        if results is None:
            # A target with a null result means argot check failed to build/analyze it
            # entirely (e.g. a Go toolchain mismatch) rather than reporting per-summary
            # errors; surface this loudly instead of silently treating it as "no results".
            console.print(
                f"[red]Warning: target {target_name!r} has no results in the check "
                "report (argot check likely failed to build it); see the .log file.[/red]"
            )
            continue
        for r in results:
            grouped.setdefault(r.get("SummaryName", ""), []).append(r)
    return grouped


def _load_summary_entries(summaries_paths: List[Path]) -> List[Dict[str, Any]]:
    entries = []
    for path in summaries_paths:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        entries.extend(data.get("dataflow-summaries", []))
    return entries


def _summary_entry_name(entry: Dict[str, Any]) -> str:
    """Reconstruct the exact string produced by the corresponding Go
    summaries.FrontendDataflowSummary.Name() implementation (frontend.go), so that entries
    loaded from a summaries YAML file line up with SummaryName values in a check-report.json."""
    if "interface" in entry:
        return f"({entry['package']}.{entry['interface']}).{entry['method']}"
    if "receiver" in entry:
        receiver = entry["receiver"]
        if receiver.startswith("*"):
            return f"(*{entry['package']}.{receiver[1:]}).{entry['method']}"
        return f"({entry['package']}.{receiver}).{entry['method']}"
    return f"{entry['package']}.{entry['function']}"


def _flow_count(summary: Dict[str, List[str]]) -> int:
    """Count individual flow edges in a DetailedSummary-shaped {source: [dest, ...]} map."""
    return sum(len(dests) for dests in (summary or {}).values())


def _excess_flow_count(want: Dict[str, List[str]], got: Dict[str, List[str]]) -> int:
    """Count flow edges present in got but not in want."""
    want = want or {}
    got = got or {}
    excess = 0
    for src, dests in got.items():
        want_dests = set(want.get(src, []))
        for d in dests:
            if d not in want_dests:
                excess += 1
    return excess


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
