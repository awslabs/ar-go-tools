#!/usr/bin/env python3
"""
Experiment runner for comparing taint analysis with and without AI-generated summaries.

This script runs experiments to measure the efficiency of the summarizer by comparing:
1. Taint analysis with AI-generated summaries
2. Baseline taint analysis without summaries
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich import box

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class ExperimentRunner:
    """Runs experiments comparing taint analysis approaches."""

    def __init__(self, repo_dir: Path, output_dir: Path, timeout: int = 300,
                 constructive_timeout: int = 180, aws_profile: Optional[str] = None):
        self.repo_dir = repo_dir
        self.output_dir = output_dir
        self.timeout = timeout
        self.constructive_timeout = constructive_timeout
        self.aws_profile = aws_profile
        self.repo_name = repo_dir.name
        self.timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')

    def _run_with_progress(self, cmd: List[str], log_file: Path, label: str,
                           timeout: Optional[int], env: Optional[Dict] = None) -> Tuple[int, float, bool]:
        """Run a subprocess with a live progress bar showing elapsed time vs timeout.

        Returns (exit_code, duration, timed_out).
        """
        start_time = time.time()
        timed_out = False
        exit_code = 0

        with open(log_file, 'w') as f:
            proc = subprocess.Popen(
                cmd, cwd=self.repo_dir, stdout=f, stderr=subprocess.STDOUT, env=env)

        try:
            total = timeout if timeout else 360
            with Progress(
                TextColumn("[bold]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(label, total=total)
                while proc.poll() is None:
                    elapsed = time.time() - start_time
                    if timeout:
                        progress.update(task, completed=min(elapsed, total))
                        if elapsed >= timeout:
                            proc.kill()
                            proc.wait()
                            timed_out = True
                            break
                    else:
                        # No timeout: pulse the bar based on elapsed minutes
                        progress.update(task, completed=elapsed % total)
                    time.sleep(0.25)
                if not timed_out:
                    progress.update(task, completed=total)

            if not timed_out:
                exit_code = proc.returncode
        except Exception as e:
            proc.kill()
            proc.wait()
            logger.error(f"{label} failed: {e}")
            exit_code = -1

        duration = time.time() - start_time
        status = "timed out" if timed_out else f"exit code {exit_code}"
        console.print(f"  [dim]{label}:[/dim] {duration:.1f}s ({status})")
        return exit_code, duration, timed_out

    def get_config_path(self) -> str:
        """Get config path based on repository."""
        if self.repo_name == "atlas":
            return "cmd/atlas/argot-config.yaml"
        return "argot-config.yaml"

    def get_spec_path(self) -> str:
        """Get user-specs path based on repository."""
        if self.repo_name == "atlas":
            return "cmd/atlas/user-specs.yaml"
        return "user-specs.yaml"

    def verify_setup(self) -> bool:
        """Verify repository has required files."""
        config_path = self.repo_dir / self.get_config_path()
        to_summarize = self.repo_dir / "to_summarize.json"

        if not config_path.exists():
            logger.error(f"Config file not found: {config_path}")
            return False

        if not to_summarize.exists():
            logger.error(f"to_summarize.json not found: {to_summarize}")
            return False

        # Create empty user-specs.yaml if missing
        spec_path = self.repo_dir / self.get_spec_path()
        if not spec_path.exists():
            logger.info(f"Creating empty user-specs.yaml")
            spec_path.write_text("dataflow-summaries: []\n")

        return True

    def run_summarization(self, log_dir: Path) -> Dict:
        """Phase 1: Run summary generation."""
        logger.info(
            f"Phase 1: Running summary generation for {self.repo_name}")

        spec_path = self.repo_dir / self.get_spec_path()
        config_path = self.get_config_path()

        # Backup existing specs
        backup_path = spec_path.with_suffix('.yaml.backup')
        if spec_path.exists():
            shutil.copy(spec_path, backup_path)

        # Clear specs
        spec_path.write_text("dataflow-summaries: []\n")

        # Run summarization
        log_file = log_dir / "summarize.log"
        stats_file = log_dir / "summarize-stats.json"

        cmd = [
            "argot-summarize",
            "--config", config_path,
            "--functions", "to_summarize.json",
            "--stats-json", str(stats_file)
        ]

        # Set up environment with AWS profile if provided
        env = os.environ.copy()
        if self.aws_profile:
            env['AWS_PROFILE'] = self.aws_profile

        exit_code, duration, _ = self._run_with_progress(
            cmd, log_file, "📝 Summary generation", timeout=None, env=env)

        # Backup generated summaries to results dir
        if spec_path.exists():
            backup_summaries = log_dir / "generated-summaries.yaml"
            shutil.copy(spec_path, backup_summaries)

        # Run argot check to get accurate soundness counts
        summaries = self._check_summaries(log_dir)

        # Load stats from JSON if available
        tool_calls = 0
        stats_data = None
        if stats_file.exists():
            try:
                stats_data = json.loads(stats_file.read_text())
                tool_calls = stats_data.get('tools', {}).get('total_calls', 0)
            except Exception as e:
                logger.warning(f"Failed to load stats JSON: {e}")

        result = {
            "duration_seconds": round(duration, 2),
            "tool_calls": tool_calls,
            "summaries": summaries,
            "exit_code": exit_code,
            "stats": stats_data
        }

        logger.info(
            f"Summary generation completed in {duration:.1f}s (exit code: {exit_code})")
        logger.info(f"Generated summaries: {summaries}")

        return result

    def run_taint_analysis(self, log_dir: Path, phase_name: str, clear_specs: bool = False) -> Dict:
        """Run taint analysis and collect results."""
        if clear_specs:
            spec_path = self.repo_dir / self.get_spec_path()
            spec_path.write_text("dataflow-summaries: []\n")

        config_path = self.get_config_path()
        log_file = log_dir / f"taint-{phase_name}.log"
        cmd = ["argot", "taint", "-config", config_path]

        exit_code, duration, timed_out = self._run_with_progress(
            cmd, log_file, f"🔍 Taint ({phase_name})", timeout=self.timeout)

        # Parse dataflows from output
        dataflows = self._parse_dataflows(log_file)

        result = {
            "duration_seconds": round(duration, 2),
            "timeout": timed_out,
            "dataflows": dataflows,
            "exit_code": exit_code
        }

        return result

    def run_constructive_check(self, log_dir: Path) -> Dict:
        """Run constructive summary generation via argot check --via naive."""
        config_path = self.get_config_path()
        log_file = log_dir / "constructive.log"
        cmd = ["argot", "check", "--config", config_path, "--via", "naive"]

        exit_code, duration, timed_out = self._run_with_progress(
            cmd, log_file, "🔨 Constructive check", timeout=self.constructive_timeout)

        return {
            "duration_seconds": round(duration, 2),
            "timeout": timed_out,
            "exit_code": exit_code
        }

    def aggregate_results(self, summarization: Dict, taint_with: Dict, taint_baseline: Dict,
                          constructive: Dict) -> Dict:
        """Phase 5: Aggregate all results."""
        logger.info(f"Phase 5: Aggregating results for {self.repo_name}")

        sum_duration = summarization["duration_seconds"]
        with_duration = taint_with["duration_seconds"]
        baseline_duration = taint_baseline["duration_seconds"]
        constructive_duration = constructive["duration_seconds"]

        # Calculate speedup
        speedup = None
        if baseline_duration > 0 and with_duration > 0:
            speedup = round(baseline_duration / with_duration, 2)

        total_with_overhead = sum_duration + with_duration

        # Check if dataflows match (compare sets of source+sink locations)
        dataflows_match = None
        if not taint_with["timeout"] and not taint_baseline["timeout"]:
            with_set = {(df['source'], df['sink'])
                        for df in taint_with["dataflows"]}
            baseline_set = {(df['source'], df['sink'])
                            for df in taint_baseline["dataflows"]}
            dataflows_match = with_set == baseline_set

        report = {
            "repo": self.repo_name,
            "timestamp": self.timestamp,
            "timeout_seconds": self.timeout,
            "constructive_timeout_seconds": self.constructive_timeout,
            "summarization": summarization,
            "taint_with_summaries": taint_with,
            "taint_baseline": taint_baseline,
            "constructive": constructive,
            "comparison": {
                "speedup_factor": speedup,
                "summary_overhead_seconds": sum_duration,
                "total_with_summaries_seconds": total_with_overhead,
                "baseline_seconds": baseline_duration,
                "constructive_seconds": constructive_duration,
                "agentic_vs_constructive_speedup": round(constructive_duration / sum_duration, 2) if constructive_duration > 0 and sum_duration > 0 else None,
                "dataflows_match": dataflows_match
            }
        }

        return report

    def restore_specs(self):
        """Restore backed up user-specs.yaml."""
        spec_path = self.repo_dir / self.get_spec_path()
        backup_path = spec_path.with_suffix('.yaml.backup')

        if backup_path.exists():
            shutil.move(backup_path, spec_path)
            logger.info(f"Restored original user-specs.yaml")

    def run(self) -> Optional[Dict]:
        """Run complete experiment."""
        logger.info(f"Starting experiment for repository: {self.repo_name}")

        # Verify setup
        if not self.verify_setup():
            return None

        # Create output directory
        repo_output = self.output_dir / self.repo_name / self.timestamp
        log_dir = repo_output / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Phase 1: Summarization
            summarization = self.run_summarization(log_dir)
            (repo_output / "summarization.json").write_text(
                json.dumps(summarization, indent=2)
            )

            # Phase 2: Taint with summaries
            taint_with = self.run_taint_analysis(
                log_dir, "with-summaries", clear_specs=False)
            (repo_output / "taint-with-summaries.json").write_text(
                json.dumps(taint_with, indent=2)
            )

            # Phase 3: Constructive summary generation (needs generated summaries still in place)
            constructive = self.run_constructive_check(log_dir)
            (repo_output / "constructive.json").write_text(
                json.dumps(constructive, indent=2)
            )

            # Phase 4: Baseline taint (clears specs)
            taint_baseline = self.run_taint_analysis(
                log_dir, "baseline", clear_specs=True)
            (repo_output / "taint-baseline.json").write_text(
                json.dumps(taint_baseline, indent=2)
            )

            # Phase 5: Aggregate
            report = self.aggregate_results(
                summarization, taint_with, taint_baseline, constructive)
            report_path = repo_output / "report.json"
            report_path.write_text(json.dumps(report, indent=2))

            logger.info(f"Experiment completed for {self.repo_name}")
            logger.info(f"Results: {report_path}")

            return report

        finally:
            # Always restore specs
            self.restore_specs()

    def _check_summaries(self, log_dir: Path) -> Dict[str, int]:
        """Run argot check to get accurate summary counts."""
        config_path = self.get_config_path()
        check_log = log_dir / "check.log"

        cmd = ["argot", "check", "--config", config_path]

        try:
            with open(check_log, 'w') as f:
                subprocess.run(
                    cmd,
                    cwd=self.repo_dir,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    timeout=360  # Short timeout for check
                )
        except Exception as e:
            logger.warning(f"argot check failed: {e}")

        # Parse output for summary counts
        if check_log.exists():
            content = check_log.read_text()
            m = re.search(
                r'Check results:\s*(\d+)\s*sound\s*/\s*(\d+)\s*soundy\s*/\s*(\d+)\s*unsound', content)
            if m:
                sound, soundy, unsound = int(m.group(1)), int(
                    m.group(2)), int(m.group(3))
                return {
                    "sound": sound,
                    "soundy": soundy,
                    "unsound": unsound,
                    "total": sound + soundy + unsound
                }

        return {"sound": 0, "soundy": 0, "unsound": 0, "total": 0}

    def _count_summaries(self, spec_path: Path) -> Dict[str, int]:
        """Count summaries by type from user-specs.yaml."""
        if not spec_path.exists():
            return {"sound": 0, "soundy": 0, "unsound": 0, "total": 0}

        content = spec_path.read_text()
        sound = content.count("type: sound")
        soundy = content.count("type: soundy")
        unsound = content.count("type: unsound")

        return {
            "sound": sound,
            "soundy": soundy,
            "unsound": unsound,
            "total": sound + soundy + unsound
        }

    def _parse_dataflows(self, log_file: Path) -> List[Dict[str, str]]:
        """Parse dataflows from taint analysis log."""
        if not log_file.exists():
            return []

        content = log_file.read_text()
        dataflows = []

        lines = content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]

            # Look for dataflow summary entries
            if line.startswith('[WARN]') and 'Data from a source has reached a sink' in line:
                source_loc = None
                sink_loc = None

                # Next lines have Source and Sink with locations
                j = i + 1
                while j < len(lines) and j < i + 10:  # Look ahead max 10 lines
                    if '\tSource:' in lines[j]:
                        # Location is on next line
                        if j + 1 < len(lines):
                            source_loc = lines[j + 1].strip()
                    elif '\tSink:' in lines[j]:
                        # Location is on next line
                        if j + 1 < len(lines):
                            sink_loc = lines[j + 1].strip()
                            break  # Found both, stop looking
                    j += 1

                if source_loc and sink_loc:
                    dataflows.append({
                        'source': source_loc,
                        'sink': sink_loc
                    })

            i += 1

        return dataflows


def get_all_repos(base_dir: Path) -> List[Path]:
    """Find all repositories with required config files."""
    repos = []
    for item in base_dir.iterdir():
        if not item.is_dir():
            continue

        # Check for config and to_summarize.json
        config_exists = (
            (item / "argot-config.yaml").exists() or
            (item / "cmd/atlas/argot-config.yaml").exists()
        )
        to_summarize_exists = (item / "to_summarize.json").exists()

        if config_exists and to_summarize_exists:
            repos.append(item)

    return sorted(repos)


def display_report(report: Dict):
    """Display experiment report in a readable format."""
    console.print()

    # Header
    header = f"[bold cyan]Experiment Report: {report['repo']}[/bold cyan]\n"
    header += f"[dim]Timestamp: {report['timestamp']} | Timeout: {report['timeout_seconds']}s[/dim]"
    console.print(Panel(header, box=box.DOUBLE))

    # Summarization
    summ = report['summarization']
    summ_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    summ_table.add_column(style="cyan")
    summ_table.add_column(style="white")

    exit_color = "green" if summ['exit_code'] == 0 else "red"
    summ_table.add_row("Duration", f"{summ['duration_seconds']}s")
    summ_table.add_row(
        "Exit Code", f"[{exit_color}]{summ['exit_code']}[/{exit_color}]")
    summ_table.add_row("Tool Calls", str(summ['tool_calls']))
    summ_table.add_row(
        "Summaries", f"[bold]{summ['summaries']['total']}[/bold] (sound: {summ['summaries']['sound']}, soundy: {summ['summaries']['soundy']}, unsound: {summ['summaries']['unsound']})")

    console.print(Panel(
        summ_table, title="[bold yellow]📝 Summary Generation[/bold yellow]", border_style="yellow"))

    # Taint analyses side by side
    with_summ = report['taint_with_summaries']
    baseline = report['taint_baseline']

    taint_table = Table(box=box.ROUNDED, show_header=True)
    taint_table.add_column("Metric", style="cyan")
    taint_table.add_column("With Summaries", style="green", justify="right")
    taint_table.add_column("Baseline", style="blue", justify="right")

    # Duration
    taint_table.add_row(
        "Duration", f"{with_summ['duration_seconds']}s", f"{baseline['duration_seconds']}s")

    # Timeout
    with_timeout = "[red]Yes[/red]" if with_summ['timeout'] else "[green]No[/green]"
    base_timeout = "[red]Yes[/red]" if baseline['timeout'] else "[green]No[/green]"
    taint_table.add_row("Timeout", with_timeout, base_timeout)

    # Exit code
    with_exit_color = "green" if with_summ['exit_code'] == 0 else "yellow" if with_summ['exit_code'] == 2 else "red"
    base_exit_color = "green" if baseline['exit_code'] == 0 else "yellow" if baseline['exit_code'] == 2 else "red"
    taint_table.add_row("Exit Code", f"[{with_exit_color}]{with_summ['exit_code']}[/{with_exit_color}]",
                        f"[{base_exit_color}]{baseline['exit_code']}[/{base_exit_color}]")

    # Dataflows
    taint_table.add_row(
        "Dataflows", f"[bold]{len(with_summ['dataflows'])}[/bold]", f"[bold]{len(baseline['dataflows'])}[/bold]")

    console.print(Panel(
        taint_table, title="[bold magenta]🔍 Taint Analysis Comparison[/bold magenta]", border_style="magenta"))

    # Constructive summary generation
    if 'constructive' in report:
        constr = report['constructive']
        constr_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        constr_table.add_column(style="cyan")
        constr_table.add_column(style="white")

        exit_color = "green" if constr['exit_code'] == 0 else "red"
        constr_table.add_row("Duration", f"{constr['duration_seconds']}s")
        constr_table.add_row(
            "Exit Code", f"[{exit_color}]{constr['exit_code']}[/{exit_color}]")
        constr_table.add_row(
            "Timed Out", "[red]Yes[/red]" if constr['timeout'] else "[green]No[/green]")

        console.print(Panel(
            constr_table, title="[bold blue]🔨 Constructive Summary Generation[/bold blue]", border_style="blue"))

    # Comparison summary
    comp = report['comparison']
    comp_parts = []

    speedup = comp['speedup_factor']
    if speedup:
        speedup_color = "green" if speedup > 1.0 else "yellow" if speedup > 0.8 else "red"
        comp_parts.append(
            f"Speedup: [{speedup_color}]{speedup:.2f}x[/{speedup_color}]")
    else:
        comp_parts.append("Speedup: [dim]N/A[/dim]")

    comp_parts.append(f"Summary Overhead: {comp['summary_overhead_seconds']}s")

    agentic_vs_constr = comp.get('agentic_vs_constructive_speedup')
    if agentic_vs_constr:
        c_color = "green" if agentic_vs_constr > 1.0 else "red"
        comp_parts.append(
            f"Constructive/Agentic: [{c_color}]{agentic_vs_constr:.2f}x[/{c_color}]")
    else:
        comp_parts.append("Constructive/Agentic: [dim]N/A[/dim]")

    if comp['dataflows_match'] is not None:
        match_str = "[green]✅ Match[/green]" if comp['dataflows_match'] else "[red]❌ Differ[/red]"
        comp_parts.append(f"Dataflows: {match_str}")
    else:
        comp_parts.append("Dataflows: [dim]N/A[/dim]")

    console.print(Panel(" | ".join(comp_parts),
                  title="[bold]📊 Summary[/bold]", border_style="dim"))
    console.print()


def list_experiments(output_dir: Path) -> List[Tuple[Path, Dict]]:
    """List all available experiment reports."""
    experiments = []

    if not output_dir.exists():
        return experiments

    for repo_dir in output_dir.iterdir():
        if not repo_dir.is_dir():
            continue

        for timestamp_dir in repo_dir.iterdir():
            if not timestamp_dir.is_dir():
                continue

            report_file = timestamp_dir / "report.json"
            if report_file.exists():
                try:
                    report = json.loads(report_file.read_text())
                    experiments.append((report_file, report))
                except Exception as e:
                    logger.warning(f"Failed to load report {report_file}: {e}")

    return sorted(experiments, key=lambda x: x[1]['timestamp'], reverse=True)


def interactive_select_experiment(output_dir: Path) -> Optional[Path]:
    """Interactive menu to select an experiment."""
    experiments = list_experiments(output_dir)

    if not experiments:
        console.print("[yellow]No experiments found.[/yellow]")
        return None

    table = Table(title="Available Experiments", box=box.ROUNDED)
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Repository", style="green")
    table.add_column("Timestamp", style="blue")
    table.add_column("Summaries", justify="right", style="yellow")
    table.add_column("Speedup", justify="right")
    table.add_column("Exit", justify="right")

    for idx, (path, report) in enumerate(experiments, 1):
        repo = report['repo']
        timestamp = report['timestamp']
        summ_exit = report['summarization']['exit_code']
        summ_count = report['summarization']['summaries']['total']
        speedup = report['comparison']['speedup_factor']

        speedup_str = f"{speedup:.2f}x" if speedup else "N/A"
        if speedup and speedup > 1.0:
            speedup_str = f"[green]{speedup_str}[/green]"
        elif speedup and speedup > 0.8:
            speedup_str = f"[yellow]{speedup_str}[/yellow]"
        elif speedup:
            speedup_str = f"[red]{speedup_str}[/red]"

        exit_color = "green" if summ_exit == 0 else "red"

        table.add_row(
            str(idx),
            repo,
            timestamp,
            str(summ_count),
            speedup_str,
            f"[{exit_color}]{summ_exit}[/{exit_color}]"
        )

    console.print(table)

    try:
        choice = console.input(
            "\n[cyan]Select experiment number (or 'q' to quit):[/cyan] ").strip()
        if choice.lower() == 'q':
            return None

        idx = int(choice) - 1
        if 0 <= idx < len(experiments):
            return experiments[idx][0]
        else:
            console.print("[red]Invalid selection.[/red]")
            return None
    except (ValueError, KeyboardInterrupt):
        return None


def clear_experiments(output_dir: Path, repo: Optional[str] = None):
    """Clear experiment results."""
    if not output_dir.exists():
        console.print("[yellow]No results directory found.[/yellow]")
        return

    if repo:
        # Clear specific repo
        repo_dir = output_dir / repo
        if repo_dir.exists():
            confirm = console.input(
                f"[red]Delete all experiments for '{repo}'? (yes/no):[/red] ").strip().lower()
            if confirm == 'yes':
                shutil.rmtree(repo_dir)
                console.print(
                    f"[green]✓ Deleted experiments for {repo}[/green]")
            else:
                console.print("[yellow]Cancelled.[/yellow]")
        else:
            console.print(
                f"[yellow]No experiments found for repository: {repo}[/yellow]")
    else:
        # Clear all
        confirm = console.input(
            "[red]Delete ALL experiment results? (yes/no):[/red] ").strip().lower()
        if confirm == 'yes':
            shutil.rmtree(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            console.print("[green]✓ Deleted all experiment results[/green]")
        else:
            console.print("[yellow]Cancelled.[/yellow]")


def show_command(output_dir: Path, repo: Optional[str] = None):
    """Show experiment results."""
    if repo:
        # Show latest for specific repo
        experiments = [e for e in list_experiments(
            output_dir) if e[1]['repo'] == repo]
        if experiments:
            report_path, report = experiments[0]
            display_report(report)
        else:
            console.print(
                f"[yellow]No experiments found for repository: {repo}[/yellow]")
    else:
        # Interactive selection
        report_path = interactive_select_experiment(output_dir)
        if report_path:
            report = json.loads(report_path.read_text())
            display_report(report)


def main():
    parser = argparse.ArgumentParser(
        description="Run experiments comparing taint analysis with and without AI-generated summaries"
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Run command
    run_parser = subparsers.add_parser('run', help='Run experiments')
    run_parser.add_argument(
        "repo",
        help="Repository name (e.g., 'sample') or 'all' for all repositories"
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Timeout for taint analysis in seconds (default: 600)"
    )
    run_parser.add_argument(
        "--constructive-timeout",
        type=int,
        default=600,
        help="Timeout for constructive summary generation in seconds (default: 600)"
    )
    run_parser.add_argument(
        "--aws-profile",
        help="AWS profile to use for argot-summarize"
    )
    run_parser.add_argument(
        "--output",
        type=Path,
        help="Output directory for results (default: ../payload/public-repos-checks/results)"
    )
    run_parser.add_argument(
        "--base-dir",
        type=Path,
        help="Base directory containing repositories (default: ../payload/public-repos-checks)"
    )

    # Show command
    show_parser = subparsers.add_parser(
        'show', help='Display experiment results')
    show_parser.add_argument(
        "repo",
        nargs='?',
        help="Repository name (optional, interactive selection if not provided)"
    )
    show_parser.add_argument(
        "--output",
        type=Path,
        help="Output directory for results (default: ../payload/public-repos-checks/results)"
    )

    # Clear command
    clear_parser = subparsers.add_parser(
        'clear', help='Clear experiment results')
    clear_parser.add_argument(
        "repo",
        nargs='?',
        help="Repository name (optional, clears all if not provided)"
    )
    clear_parser.add_argument(
        "--output",
        type=Path,
        help="Output directory for results (default: ../payload/public-repos-checks/results)"
    )

    args = parser.parse_args()

    # Set defaults relative to script location
    script_dir = Path(__file__).parent

    # Handle commands
    if args.command == 'show':
        output_dir = args.output or script_dir.parent / \
            "payload" / "public-repos-checks" / "results"
        show_command(output_dir, args.repo)
        return 0

    elif args.command == 'clear':
        output_dir = args.output or script_dir.parent / \
            "payload" / "public-repos-checks" / "results"
        clear_experiments(output_dir, args.repo)
        return 0

    elif args.command == 'run':
        base_dir = args.base_dir or script_dir.parent / "payload" / "public-repos-checks"
        output_dir = args.output or base_dir / "results"

        if not base_dir.exists():
            logger.error(f"Base directory not found: {base_dir}")
            return 1

        # Check dependencies
        for cmd in ["argot", "argot-summarize"]:
            if shutil.which(cmd) is None:
                logger.error(f"Required command not found: {cmd}")
                return 1

        output_dir.mkdir(parents=True, exist_ok=True)

        if args.repo == "all":
            logger.info("Running experiments on all repositories")
            repos = get_all_repos(base_dir)
            logger.info(
                f"Found {len(repos)} repositories: {[r.name for r in repos]}")

            aggregate_results = []

            for repo_dir in repos:
                logger.info(f"\n{'='*60}")
                logger.info(f"Processing {repo_dir.name}...")
                logger.info(f"{'='*60}\n")

                runner = ExperimentRunner(
                    repo_dir, output_dir, args.timeout, args.constructive_timeout, args.aws_profile)
                report = runner.run()

                if report:
                    aggregate_results.append(report)

            # Write aggregate results
            timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
            aggregate_path = output_dir / f"aggregate-{timestamp}.json"
            aggregate_path.write_text(json.dumps(aggregate_results, indent=2))

            logger.info(f"\nAll experiments completed")
            logger.info(f"Aggregate results: {aggregate_path}")

        else:
            repo_dir = base_dir / args.repo
            if not repo_dir.exists():
                logger.error(f"Repository directory not found: {repo_dir}")
                return 1

            runner = ExperimentRunner(
                repo_dir, output_dir, args.timeout, args.constructive_timeout, args.aws_profile)
            report = runner.run()

            if not report:
                return 1

        return 0

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
