#!/usr/bin/env python3
"""
Experiment runner for the dataflow-soundness-checker evaluation.

All generated output goes under experiment/runs/<run-id>/{generated-configs,llm-summaries,
results}/<repo>/. The run ID defaults to a UTC timestamp (YYYY-MM-DD_HH-MM-SSZ) and can be
set explicitly via --run-id. Shared inputs (argot-configs, ground-truth-summaries,
interesting-methods) remain in experiment/.

Producer commands accept --repo all to run once per repo (failures logged, not fatal).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
from rich.console import Console

console = Console()

EXPERIMENT_DIR = Path(__file__).parent
REPOS_BASE_DIR = EXPERIMENT_DIR.parent / "payload" / "public-repos-checks"
GROUND_TRUTH_DIR = EXPERIMENT_DIR / "ground-truth-summaries"
ARGOT_CONFIGS_DIR = EXPERIMENT_DIR / "argot-configs"
INTERESTING_METHODS_DIR = EXPERIMENT_DIR / "interesting-methods"
RUNS_DIR = EXPERIMENT_DIR / "runs"
EVAL_CHECKER_BIN = os.environ.get("EVAL_CHECKER_BIN")

REPOS = {
    "amazon-ssm-agent": "ef5df636f7035bb1e3e325fab519379715678033",
    "badger": "a700dc3b6332e2351674f34f841233541568f782",
    "govatar": "31618c34a7ae828c61629e022b1654e4ec552628",
    "prometheus": "7ba246a648ca4e294ca008d95b6fcc8df2f9c255",
    "sample": "",
}
ALL_REPOS = "all"


# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    repo_choices = sorted(REPOS)

    # Producers with --repo all support
    for name, fn, extras in [
        (
            "run-check",
            cmd_run_check,
            [
                ("--variant", {"required": True, "choices": ["ground-truth", "llm"]}),
            ],
        ),
        (
            "run-constructive",
            cmd_run_constructive,
            [
                ("--methods", {"type": Path}),
            ],
        ),
        (
            "run-llm-summarization",
            cmd_run_llm_summarization,
            [
                ("--target", {}),
                ("--model", {"default": "anthropic.claude-sonnet-5"}),
                ("--inference-profile", {}),
                ("--fresh", {"action": "store_true"}),
            ],
        ),
        (
            "run-taint",
            cmd_run_taint,
            [
                (
                    "--variant",
                    {
                        "default": "baseline",
                        "choices": ["baseline", "ground-truth", "llm"],
                    },
                ),
            ],
        ),
    ]:
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True, choices=repo_choices + [ALL_REPOS])
        p.add_argument("--run-id")
        for arg_name, kwargs in extras:
            p.add_argument(arg_name, **kwargs)  # ty: ignore[invalid-argument-type]
        p.set_defaults(func=fn)

    # Eval commands
    for name, fn, extras in [
        (
            "eval-checker-precision",
            cmd_eval_checker_precision,
            [
                ("--check-report", {"required": True, "type": Path}),
                ("--constructive-report", {"required": True, "type": Path}),
                ("--summaries", {"type": Path}),
            ],
        ),
        (
            "eval-checker-efficiency",
            cmd_eval_checker_efficiency,
            [
                ("--check-report", {"required": True, "type": Path}),
                ("--constructive-report", {"required": True, "type": Path}),
                ("--summaries", {"type": Path}),
            ],
        ),
        (
            "eval-checker-ablation",
            cmd_eval_checker_ablation,
            [
                ("--check-report", {"required": True, "type": Path}),
                ("--summaries", {"type": Path}),
            ],
        ),
        (
            "eval-llm-effectiveness",
            cmd_eval_llm_effectiveness,
            [
                ("--check-report", {"required": True, "type": Path}),
                ("--constructive-report", {"required": True, "type": Path}),
                ("--summaries", {"required": True, "type": Path}),
            ],
        ),
        (
            "eval-workflow-efficiency",
            cmd_eval_workflow_efficiency,
            [
                ("--summarization", {"required": True, "type": Path}),
                ("--check-report", {"required": True, "type": Path}),
                ("--taint-with-summaries", {"required": True, "type": Path}),
                ("--taint-baseline", {"required": True, "type": Path}),
                ("--constructive-report", {"required": True, "type": Path}),
            ],
        ),
    ]:
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True, choices=repo_choices)
        p.add_argument("--run-id")
        for arg_name, kwargs in extras:
            p.add_argument(arg_name, **kwargs)  # ty: ignore[invalid-argument-type]
        p.set_defaults(func=fn)

    args = parser.parse_args()
    run_id = args.run_id or generate_run_id()
    run = init_run(run_id, sys.argv[1:])
    args.run = run
    console.print(f"[bold]Run:[/bold] {run_id}  ({run.root})")

    if getattr(args, "repo", None) == ALL_REPOS:
        failed = []
        for repo in sorted(REPOS):
            args.repo = repo
            console.print(f"[bold]=== {args.command} --repo {repo} ===[/bold]")
            mark_task(run, args.command, repo, "running")
            try:
                args.func(args)
                mark_task(run, args.command, repo, "complete")
            except SystemExit as e:
                if e.code not in (0, None):
                    console.print(
                        f"[red]{args.command} --repo {repo} failed (exit {e.code})[/red]"
                    )
                    mark_task(run, args.command, repo, "failed", error=f"exit {e.code}")
                    failed.append(repo)
                else:
                    mark_task(run, args.command, repo, "complete")
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]{args.command} --repo {repo} failed ({e})[/red]")
                mark_task(run, args.command, repo, "failed", error=str(e))
                failed.append(repo)
        finalize_run(run, failed=bool(failed))
        return 1 if failed else 0
    else:
        repo = getattr(args, "repo", None) or "all"
        mark_task(run, args.command, repo, "running")
        try:
            args.func(args)
            mark_task(run, args.command, repo, "complete")
        except SystemExit as e:
            mark_task(run, args.command, repo, "failed", error=f"exit {e.code}")
            finalize_run(run, failed=True)
            return e.code if isinstance(e.code, int) else 1
        finalize_run(run, failed=False)
        return 0


# ---------------------------------------------------------------------------
# Producer commands
# ---------------------------------------------------------------------------


def cmd_run_check(args: argparse.Namespace) -> None:
    run: RunPaths = args.run
    generate_configs(args.repo, run)
    out = run.result_path(args.repo, f"run-check-{args.variant}-results")
    repo_path = _repo_dir(args.repo)
    (repo_path / "logs" / "argot").mkdir(parents=True, exist_ok=True)

    merged: Dict[str, Any] = {}
    total_duration = 0.0
    found = False
    for kind in ("functions", "interfaces"):
        config = run.config_dir(args.repo) / f"check-{args.variant}-split-{kind}.yaml"
        if not config.exists():
            continue
        found = True
        part_out = out.with_suffix(f".{kind}.json")
        log_file = part_out.with_suffix(".log")
        try:
            duration = _run_subprocess(
                ["argot", "check", "-config", str(config.resolve()), "-via", "all"],
                cwd=repo_path,
                log_file=log_file,
                label=f"run-check ({args.repo}, {args.variant}, {kind})",
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            console.print(f"[red]run-check {kind} failed ({e}); null result[/red]")
            merged.setdefault(kind, None)
            continue
        report_path = _find_check_report(log_file)
        if not report_path:
            sys.exit(1)
        total_duration += duration
        for target, results in json.loads(report_path.read_text()).items():
            merged[f"{target}:{kind}"] = results
        log_file.unlink(missing_ok=True)

    if not found:
        console.print(
            f"[red]No split configs for {args.repo}/{args.variant}; "
            "ensure LLM summaries exist before checking variant=llm[/red]"
        )
        sys.exit(1)
    out.write_text(json.dumps(merged, indent=2))
    console.print(f"[green]Wrote {out}[/green] ({total_duration:.1f}s)")


def cmd_run_constructive(args: argparse.Namespace) -> None:
    run: RunPaths = args.run
    generate_configs(args.repo, run)
    paths = [args.methods] if args.methods else _ground_truth_files(args.repo)
    out = run.result_path(args.repo, "run-constructive-results")
    repo_path = _repo_dir(args.repo)
    (repo_path / "logs" / "argot").mkdir(parents=True, exist_ok=True)

    merged: Dict[str, Any] = {}
    total_duration = 0.0
    for p in paths:
        config = run.config_dir(args.repo) / f"check-ground-truth-{p.stem}.yaml"
        if not config.exists():
            console.print(f"[red]No generated config for {p.stem}[/red]")
            sys.exit(1)
        part_out = out.with_suffix(f".{p.stem}.json")
        log_file = part_out.with_suffix(".log")
        try:
            duration = _run_subprocess(
                ["argot", "check", "-config", str(config.resolve()), "-via", "naive"],
                cwd=repo_path,
                log_file=log_file,
                label=f"run-constructive ({args.repo}, {p.stem})",
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            console.print(
                f"[red]run-constructive {p.stem} failed ({e}); null result[/red]"
            )
            merged.setdefault(p.stem, None)
            continue
        report_path = _find_check_report(log_file)
        if not report_path:
            sys.exit(1)
        total_duration += duration
        for target, results in json.loads(report_path.read_text()).items():
            existing = merged.get(target)
            merged[target] = (existing or []) + (results or [])
        part_out.unlink(missing_ok=True)
        log_file.unlink(missing_ok=True)

    out.write_text(json.dumps(merged, indent=2))
    console.print(f"[green]Wrote {out}[/green] ({total_duration:.1f}s)")


def cmd_run_llm_summarization(args: argparse.Namespace) -> None:
    run: RunPaths = args.run
    _repo_dir(args.repo)
    generate_configs(args.repo, run)

    llm_dir = run.llm_dir(args.repo)
    llm_dir.mkdir(parents=True, exist_ok=True)
    summaries_path = llm_dir / "summaries.yaml"
    config_path = run.config_dir(args.repo) / "check-llm.yaml"
    config = yaml.safe_load(config_path.read_text())
    target_name = args.target or (config.get("targets") or [{}])[0].get("name")
    if not target_name:
        console.print(f"[red]No target in {config_path}[/red]")
        sys.exit(1)

    functions_path = INTERESTING_METHODS_DIR / args.repo / "to_summarize.json"
    if not functions_path.exists():
        console.print(f"[red]{functions_path} not found[/red]")
        sys.exit(1)
    all_functions = json.loads(functions_path.read_text())

    if args.fresh:
        for stale in llm_dir.glob("summaries-*.yaml"):
            stale.unlink()

    out = run.result_path(args.repo, "run-llm-summarization-results")
    log_file = out.with_suffix(".log")
    total_duration = 0.0
    max_attempts = 10

    for attempt in range(1, max_attempts + 1):
        num_done = len(list(llm_dir.glob("summaries-*.yaml")))
        remaining = all_functions[num_done:]
        if not remaining:
            break
        remaining_path = llm_dir / "to_summarize.remaining.json"
        remaining_path.write_text(json.dumps(remaining, indent=2))

        cmd = [
            "argot-summarize",
            "--config",
            str(config_path.resolve()),
            "--target",
            target_name,
            "--functions",
            str(remaining_path.resolve()),
            "--out-dir",
            str(llm_dir.resolve()),
            "--stats-json",
            str(llm_dir / "summarize-stats.json"),
            "--model",
            args.model,
            "--batch-size",
            "1",
        ]
        if args.inference_profile:
            cmd += ["--inference-profile", args.inference_profile]
        try:
            total_duration += _run_subprocess(
                cmd,
                cwd=llm_dir,
                log_file=log_file,
                label=f"run-llm-summarization ({args.repo}), attempt {attempt}/{max_attempts}",
                timeout=None,
            )
            remaining_path.unlink(missing_ok=True)
        except subprocess.CalledProcessError:
            remaining_path.unlink(missing_ok=True)
            if attempt == max_attempts:
                raise
            wait = min(2**attempt, 60)
            console.print(
                f"[yellow]Attempt {attempt}/{max_attempts} failed, retrying in {wait}s[/yellow]"
            )
            time.sleep(wait)

    # Consolidate batch files into one summaries.yaml
    combined: List[Any] = []
    for batch in sorted(llm_dir.glob("summaries-*.yaml")):
        data = yaml.safe_load(batch.read_text()) or {}
        combined.extend(data.get("dataflow-summaries") or [])
    summaries_path.write_text(yaml.safe_dump({"dataflow-summaries": combined}))

    stats_path = llm_dir / "summarize-stats.json"
    result = {
        "repo": args.repo,
        "duration_seconds": round(total_duration, 2),
        "stats": json.loads(stats_path.read_text()) if stats_path.exists() else None,
        "summaries_path": str(summaries_path),
    }
    out.write_text(json.dumps(result, indent=2))
    console.print(f"[green]Wrote {out}[/green] ({total_duration:.1f}s)")


def cmd_run_taint(args: argparse.Namespace) -> None:
    run: RunPaths = args.run
    repo_path = _repo_dir(args.repo)
    generate_configs(args.repo, run)
    config_path = run.config_dir(args.repo) / f"taint-{args.variant}.yaml"
    (repo_path / "logs" / "argot").mkdir(parents=True, exist_ok=True)

    out = run.result_path(args.repo, f"run-taint-{args.variant}-results")
    log_file = out.with_suffix(".log")
    duration = _run_subprocess(
        ["argot", "taint", "-config", str(config_path.resolve())],
        cwd=repo_path,
        log_file=log_file,
        label=f"run-taint ({args.repo}, {args.variant})",
        tolerate_exit_codes=(2,),
    )

    report = _read_taint_report(log_file, repo_path)
    if report["report_path"] is None:
        console.print(f"[red]run-taint failed; no report found, see {log_file}[/red]")
        sys.exit(1)
    report["duration_seconds"] = round(duration, 2)
    out.write_text(json.dumps(report, indent=2))
    console.print(f"[green]Wrote {out}[/green] ({duration:.1f}s)")


# ---------------------------------------------------------------------------
# Eval commands
# ---------------------------------------------------------------------------


def cmd_eval_checker_precision(args: argparse.Namespace) -> None:
    _run_eval_checker("precision", args, needs_constructive=True)


def cmd_eval_checker_efficiency(args: argparse.Namespace) -> None:
    _run_eval_checker("efficiency", args, needs_constructive=True)


def cmd_eval_checker_ablation(args: argparse.Namespace) -> None:
    _run_eval_checker("ablation", args, needs_constructive=False)


def cmd_eval_llm_effectiveness(args: argparse.Namespace) -> None:
    _run_eval_checker(
        "precision",
        args,
        needs_constructive=True,
        rq="llm-effectiveness",
        result_name="eval-llm-effectiveness-results",
    )


def cmd_eval_workflow_efficiency(args: argparse.Namespace) -> None:
    run: RunPaths = args.run
    summarization = json.loads(args.summarization.read_text())
    check = json.loads(args.check_report.read_text())
    taint_with = json.loads(args.taint_with_summaries.read_text())
    taint_base = json.loads(args.taint_baseline.read_text())
    constructive = json.loads(args.constructive_report.read_text())

    sum_s = summarization.get("duration_seconds") or 0
    check_s = _check_report_duration(check)
    with_s = taint_with.get("duration_seconds") or 0
    base_s = taint_base.get("duration_seconds") or 0
    constr_s = _check_report_duration(constructive)

    with_set = {
        (d["tag"], d["source"], d["sink"]) for d in taint_with.get("dataflows") or []
    }
    base_set = {
        (d["tag"], d["source"], d["sink"]) for d in taint_base.get("dataflows") or []
    }

    result = {
        "rq": "workflow-efficiency",
        "repo": args.repo,
        "summarization_seconds": sum_s,
        "check_seconds": check_s,
        "taint_with_summaries_seconds": with_s,
        "taint_baseline_seconds": base_s,
        "constructive_seconds": constr_s,
        "speedup_factor": round(base_s / with_s, 2) if base_s and with_s else None,
        "agentic_vs_constructive_speedup": round(constr_s / sum_s, 2)
        if constr_s and sum_s
        else None,
        "dataflows_match": with_set == base_set,
        "extra_dataflows_with_summaries": sorted(with_set - base_set),
        "missing_dataflows_with_summaries": sorted(base_set - with_set),
    }
    out = run.result_path(args.repo, "eval-workflow-efficiency-results")
    out.write_text(json.dumps(result, indent=2))
    console.print(f"[green]Wrote {out}[/green]")


def _run_eval_checker(
    subcommand: str,
    args: argparse.Namespace,
    needs_constructive: bool,
    rq: Optional[str] = None,
    result_name: Optional[str] = None,
) -> None:
    run: RunPaths = args.run
    summaries = [args.summaries] if args.summaries else _ground_truth_files(args.repo)
    out = run.result_path(
        args.repo, result_name or f"eval-checker-{subcommand}-results"
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
        str(out),
    ]
    for p in summaries:
        cmd += ["-summaries", str(p)]
    if needs_constructive:
        cmd += ["-constructive-report", str(args.constructive_report)]

    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout:
        console.print(r.stdout, end="")
    if r.returncode != 0:
        console.print(f"[red]eval-checker {subcommand} failed:[/red]\n{r.stderr}")
        sys.exit(1)
    if rq:
        data = json.loads(out.read_text())
        data["rq"] = rq
        out.write_text(json.dumps(data, indent=2))


def _check_report_duration(report: Dict[str, Any]) -> float:
    total_ns = sum(
        r.get("Elapsed", 0) for results in report.values() for r in (results or [])
    )
    return round(total_ns / 1e9, 2)


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------


def generate_configs(repo: str, run: RunPaths) -> List[Path]:
    """Write all argot-config.yaml files for repo into the run's generated-configs directory."""
    repo_path = _repo_dir(repo)
    out_dir = run.config_dir(repo)
    out_dir.mkdir(parents=True, exist_ok=True)
    produced: Set[str] = set()
    project_root = os.path.relpath(repo_path.resolve(), start=out_dir.resolve())

    def rel(p: Path) -> str:
        return os.path.relpath(p.resolve(), start=repo_path.resolve())

    def write_taint(name: str, user_specs: Optional[List[str]] = None) -> Path:
        cfg = _base_config(repo)
        cfg["options"]["project-root"] = project_root
        cfg["dataflow-problems"]["taint-tracking"] = _taint_specs(repo)
        cfg["dataflow-problems"]["field-sensitive-funcs"] = [".*"]
        if user_specs:
            cfg["dataflow-problems"]["user-specs"] = user_specs
        path = out_dir / name
        path.write_text(yaml.safe_dump(cfg))
        produced.add(name)
        return path

    def write_check(name: str, check_specs: List[str]) -> Path:
        cfg = _base_config(repo)
        cfg["options"]["project-root"] = project_root
        cfg["dataflow-problems"]["check-specs"] = check_specs
        path = out_dir / name
        path.write_text(yaml.safe_dump(cfg))
        produced.add(name)
        return path

    written: List[Path] = []
    gt_paths = _ground_truth_files(repo)
    llm_path = run.llm_dir(repo) / "summaries.yaml"

    written.append(write_taint("taint-baseline.yaml"))
    written.append(write_taint("taint-ground-truth.yaml", [rel(p) for p in gt_paths]))
    written.append(write_taint("taint-llm.yaml", [rel(llm_path)]))

    for gt in gt_paths:
        written.append(write_check(f"check-ground-truth-{gt.stem}.yaml", [rel(gt)]))
    written.append(write_check("check-llm.yaml", [rel(llm_path)]))

    # Split configs: pool summaries by kind (function vs interface) for isolated checking.
    def write_split(prefix: str, data_paths: List[Path]) -> None:
        if not all(p.exists() for p in data_paths):
            return
        entries: List[Dict] = []
        for p in data_paths:
            entries.extend(
                (yaml.safe_load(p.read_text()) or {}).get("dataflow-summaries") or []
            )
        funcs = [e for e in entries if not e.get("interface")]
        ifaces = [e for e in entries if e.get("interface")]
        for kind, items in [("functions", funcs), ("interfaces", ifaces)]:
            if not items:
                continue
            data_file = out_dir / f"_split-{prefix}-{kind}.yaml"
            data_file.write_text(yaml.safe_dump({"dataflow-summaries": items}))
            produced.add(data_file.name)
            written.append(
                write_check(f"check-{prefix}-split-{kind}.yaml", [rel(data_file)])
            )

    write_split("ground-truth", gt_paths)
    write_split("llm", [llm_path])

    extra = sorted(
        p.name for p in out_dir.iterdir() if p.is_file() and p.name not in produced
    )
    if extra:
        console.print(
            f"[yellow]{repo}: {len(extra)} stale file(s) in {out_dir}: {', '.join(extra)}[/yellow]"
        )
    return written


# ---------------------------------------------------------------------------
# Run paths and manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunPaths:
    root: Path

    @property
    def generated_configs(self) -> Path:
        return self.root / "generated-configs"

    @property
    def llm_summaries(self) -> Path:
        return self.root / "llm-summaries"

    @property
    def results(self) -> Path:
        return self.root / "results"

    def config_dir(self, repo: str) -> Path:
        return self.generated_configs / repo

    def llm_dir(self, repo: str) -> Path:
        return self.llm_summaries / repo

    def result_path(self, repo: str, name: str) -> Path:
        path = self.results / repo / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


def generate_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%SZ")


def init_run(run_id: str, command: List[str]) -> RunPaths:
    """Create or reopen a run directory. Writes initial manifest on creation."""
    root = RUNS_DIR / run_id
    run = RunPaths(root=root)
    if root.exists():
        return run
    root.mkdir(parents=True)
    _write_manifest(
        run,
        {
            "id": run_id,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "command": command,
            "tasks": {},
        },
    )
    return run


def mark_task(
    run: RunPaths, command: str, repo: str, status: str, error: str = ""
) -> None:
    manifest = _read_manifest(run)
    tasks = manifest.setdefault("tasks", {})
    key = f"{command}:{repo}"
    entry = tasks.get(key, {})
    entry["status"] = status
    if status == "running":
        entry["started_at"] = datetime.now(timezone.utc).isoformat()
    elif status in ("complete", "failed"):
        entry["finished_at"] = datetime.now(timezone.utc).isoformat()
    if error:
        entry["error"] = error
    tasks[key] = entry
    _write_manifest(run, manifest)


def finalize_run(run: RunPaths, failed: bool) -> None:
    manifest = _read_manifest(run)
    manifest["status"] = "failed" if failed else "complete"
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    _write_manifest(run, manifest)


def _read_manifest(run: RunPaths) -> Dict[str, Any]:
    p = run.root / "run.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _write_manifest(run: RunPaths, manifest: Dict[str, Any]) -> None:
    (run.root / "run.json").write_text(json.dumps(manifest, indent=2))


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _base_config(repo: str) -> Dict[str, Any]:
    target = yaml.safe_load((ARGOT_CONFIGS_DIR / repo / "target.yaml").read_text())
    return {
        "targets": [target],
        "dataflow-problems": {
            "summarize-on-demand": True,
            "check-ignores-unsound": True,
            "intra-timeout-ms": 60000,
        },
        "options": {
            "project-root": "./",
            "reports-dir": "logs/argot",
            "log-level": 3,
            "report-paths": True,
            "analysis-options": {"unsafe-max-depth": 35},
        },
    }


def _taint_specs(repo: str) -> List[Dict[str, Any]]:
    return yaml.safe_load((ARGOT_CONFIGS_DIR / repo / "taint-specs.yaml").read_text())


def _ground_truth_files(repo: str) -> List[Path]:
    return sorted((GROUND_TRUTH_DIR / repo).glob("*.yaml"))


def _repo_dir(repo: str) -> Path:
    d = REPOS_BASE_DIR / repo
    if not d.exists():
        console.print(f"[red]Repository directory not found: {d}[/red]")
        sys.exit(1)
    return d


def _find_check_report(log_file: Path) -> Optional[Path]:
    """Extract the check-report.json path from argot check's log output."""
    for line in log_file.read_text().splitlines():
        if "Full report written to" in line:
            p = Path(line.split("Full report written to", 1)[1].strip())
            if p.exists():
                return p
    console.print(f"[red]No check-report.json found; see {log_file}[/red]")
    return None


def _read_taint_report(log_file: Path, repo_path: Path) -> Dict[str, Any]:
    """Parse argot taint's log for its report, then read all per-flow detail files."""
    content = log_file.read_text() if log_file.exists() else ""
    m = re.search(r"Wrote final report in (\S+)", content)
    if not m:
        return {"dataflows": [], "count_by_severity": {}, "report_path": None}

    report_path = Path(m.group(1))
    if not report_path.is_absolute():
        report_path = repo_path / report_path
    if not report_path.exists():
        return {"dataflows": [], "count_by_severity": {}, "report_path": None}

    overall = json.loads(report_path.read_text())
    dataflows = []
    for tag, group in (overall.get("Reports") or {}).items():
        for detail in group.get("Details") or []:
            p = Path(detail)
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
    """Run subprocess, log output, return duration. Raises on failure."""
    console.print(f"[dim]Running {label}...[/dim]")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    with open(log_file, "w") as f:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    finally:
        duration = time.time() - start

    if proc.returncode != 0 and proc.returncode not in tolerate_exit_codes:
        tail = log_file.read_text().splitlines()[-20:]
        console.print(
            f"[red]{label} failed (exit {proc.returncode}):\n"
            + "\n".join(tail)
            + "[/red]"
        )
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    console.print(f"  [dim]{label}:[/dim] {duration:.1f}s")
    return duration


if __name__ == "__main__":
    sys.exit(main())
