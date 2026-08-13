#!/usr/bin/env python3
"""Generate dataflow summaries using Strands Agents and Argot MCP.

Each summary entry (function or interface method) is processed by its own independent agent
with its own MCP server, running concurrently via asyncio for throughput. Each entry produces
a named YAML file (e.g. fmt.Printf.yaml) so missing/failed entries are immediately visible.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml
from strands import Agent

from summary_generator.agent import (
    create_summary_agent,
    entry_filename,
    format_spec_iterm,
    WORKFLOW_PROMPT,
)

# Bedrock allows higher concurrency, but each agent spawns an argot-mcp-server subprocess
# that loads the full program into memory. 5 balances throughput against memory pressure.
DEFAULT_CONCURRENCY = 5


def load_functions_list(path: str) -> list[dict]:
    """Load function list from JSON or YAML file."""
    file_path = Path(path)
    content = file_path.read_text()
    if file_path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(content) or []
    return json.loads(content)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate dataflow summaries using Strands Agents and Argot MCP",
    )
    parser.add_argument(
        "--argot-mcp",
        default="argot-mcp-server",
        help="Path to argot-mcp-server binary",
    )
    parser.add_argument(
        "--config",
        required=True,
        nargs="+",
        help="Argot config file(s) for the program to analyze",
    )
    parser.add_argument(
        "--functions",
        required=True,
        help="JSON/YAML file with list of functions to summarize",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Directory for agent-written summary YAML files",
    )
    parser.add_argument(
        "--inference-profile",
        help="AWS Bedrock inference profile ARN (auto-detected if not specified)",
    )
    parser.add_argument(
        "--mask",
        default="",
        help="Mask for disallowed tools (comma-separated list of tool names)",
    )
    parser.add_argument(
        "--model",
        default="anthropic.claude-sonnet-5",
        help="Model ID (default: Claude Sonnet 5 for Bedrock)",
    )
    parser.add_argument(
        "--provider",
        default="bedrock",
        choices=["bedrock", "anthropic", "ollama", "openai"],
        help="LLM provider",
    )
    parser.add_argument(
        "--region", default="us-east-1", help="AWS region (for Bedrock)"
    )
    parser.add_argument(
        "--stats-json", help="Output file for aggregate statistics in JSON format"
    )
    parser.add_argument(
        "--target", default="main", help="Target name in config to analyze"
    )
    args = parser.parse_args()

    # Validate argot-mcp-server
    argot_mcp_path = args.argot_mcp
    if "/" in argot_mcp_path or "\\" in argot_mcp_path:
        if not Path(argot_mcp_path).exists():
            print(
                f"Error: argot-mcp-server not found at: {argot_mcp_path}",
                file=sys.stderr,
            )
            return 1
    else:
        if not shutil.which(argot_mcp_path):
            print(f"Error: '{argot_mcp_path}' not found on PATH", file=sys.stderr)
            return 1

    # Load function list
    try:
        functions = load_functions_list(args.functions)
    except Exception as e:
        print(f"Error loading functions list: {e}", file=sys.stderr)
        return 1

    # Resolve paths
    config_path = Path(args.config[0]).absolute()
    config_dir = config_path.parent
    with open(config_path) as f:
        loaded_config = yaml.safe_load(f) or {}
    project_root = (loaded_config.get("options") or {}).get("project-root", "")
    if not project_root:
        mcp_cwd = config_dir
    elif Path(project_root).is_absolute():
        mcp_cwd = Path(project_root)
    else:
        mcp_cwd = (config_dir / project_root).resolve()

    config_files = [
        os.path.relpath(Path(c).absolute(), start=mcp_cwd) for c in args.config
    ]
    out_dir = Path(args.out_dir).absolute()
    out_dir.mkdir(parents=True, exist_ok=True)

    model_config = {
        "provider": args.provider,
        "model_id": args.model,
        "region": args.region,
        "inference_profile": args.inference_profile,
    }

    # Build system prompt: workflow instructions + dataflow format specification.
    # The format spec is loaded once here rather than fetched as a tool call each time,
    # so it lives in the system prompt and doesn't balloon conversation history.
    repo_root = Path(out_dir).resolve()
    while repo_root != repo_root.parent:
        if (repo_root / "cmd" / "argot-mcp-server").exists():
            break
        repo_root = repo_root.parent
    prompt_file = repo_root / "cmd" / "argot-mcp-server" / "dataflow-summary-generation-prompt.txt"
    dataflow_prompt = prompt_file.read_text() if prompt_file.exists() else ""
    system_prompt = WORKFLOW_PROMPT + "\n\n" + dataflow_prompt

    # Logging — consolidated log file for all agents.
    log_file = out_dir / "summary-generator.log"
    logging.getLogger("strands").setLevel(logging.DEBUG)
    logging.basicConfig(
        filename=str(log_file),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    # Determine which tools to expose
    allowed_tools = {
        "argot_reload_config",
        "argot_load",
        "argot_show_state",
        "argot_show_src",
        "argot_show_ssa",
        "argot_list_functions",
        "argot_show_ssa_value",
        "argot_show_ssa_instr",
        "argot_function_focus",
        "argot_function_unfocus",
        "check_summary_valid",
    }
    if args.mask:
        for tool_name in args.mask.split(","):
            allowed_tools.discard(tool_name.strip())

    # Run all entries concurrently
    try:
        # Fail fast if credentials are missing (rather than spawning N agents that all fail).
        if model_config["provider"] == "bedrock":
            import boto3

            sts = boto3.client(
                "sts", region_name=model_config.get("region", "us-east-1")
            )
            try:
                sts.get_caller_identity()
            except Exception as e:
                print(f"Error: AWS credentials not available: {e}", file=sys.stderr)
                return 1

        asyncio.run(
            run_all(
                functions=functions,
                config_files=config_files,
                target=args.target,
                out_dir=out_dir,
                mcp_cwd=str(mcp_cwd),
                argot_mcp_path=argot_mcp_path,
                model_config=model_config,
                allowed_tools=allowed_tools,
                concurrency=DEFAULT_CONCURRENCY,
                system_prompt=system_prompt,
            )
        )
    except Exception as e:
        print(f"Error generating summaries: {e}", file=sys.stderr)
        return 1

    # Aggregate statistics from the consolidated log file.
    if log_file.exists() and log_file.stat().st_size > 0:
        from summary_generator.stats import compute_statistics, print_statistics

        try:
            combined_stats = compute_statistics(str(log_file))
            if combined_stats:
                print_statistics(combined_stats)
                if args.stats_json:
                    stats_out = combined_stats.copy()
                    if "session" in stats_out:
                        for k in ("start", "end"):
                            if k in stats_out["session"] and hasattr(
                                stats_out["session"][k], "isoformat"
                            ):
                                stats_out["session"][k] = stats_out["session"][
                                    k
                                ].isoformat()
                    if "tools" in stats_out and "timeline" in stats_out["tools"]:
                        stats_out["tools"]["timeline"] = [
                            (
                                ts.isoformat() if hasattr(ts, "isoformat") else ts,
                                tool,
                            )
                            for ts, tool in stats_out["tools"]["timeline"]
                        ]
                    with open(args.stats_json, "w") as f:
                        json.dump(stats_out, f, indent=2)
        except Exception:
            pass

    return 0


# ---------------------------------------------------------------------------
# Async orchestration
# ---------------------------------------------------------------------------


async def run_all(
    functions: list[dict],
    config_files: list[str],
    target: str,
    out_dir: Path,
    mcp_cwd: str,
    argot_mcp_path: str,
    model_config: dict,
    allowed_tools: set[str],
    concurrency: int,
    system_prompt: str,
) -> None:
    """Process all summary entries concurrently, one agent per entry."""
    sem = asyncio.Semaphore(concurrency)
    total = len(functions)

    async def worker(index: int, entry: dict) -> None:
        async with sem:
            label = format_spec_iterm(entry)
            out_file = entry_filename(entry)
            print(
                f"[{index + 1}/{total}] Starting {label} -> {out_file}", file=sys.stderr
            )
            try:
                await generate_one(
                    entry=entry,
                    out_file=out_file,
                    config_files=config_files,
                    target=target,
                    out_dir=out_dir,
                    mcp_cwd=mcp_cwd,
                    argot_mcp_path=argot_mcp_path,
                    model_config=model_config,
                    allowed_tools=allowed_tools,
                    system_prompt=system_prompt,
                )
                print(f"[{index + 1}/{total}] Done {label}", file=sys.stderr)
            except Exception as e:
                print(f"[{index + 1}/{total}] Failed {label}: {e}", file=sys.stderr)

    await asyncio.gather(*(worker(i, entry) for i, entry in enumerate(functions)))


async def generate_one(
    entry: dict,
    out_file: str,
    config_files: list[str],
    target: str,
    out_dir: Path,
    mcp_cwd: str,
    argot_mcp_path: str,
    model_config: dict,
    allowed_tools: set[str],
    system_prompt: str,
) -> None:
    """Create an independent agent and generate a summary for one entry."""
    model, mcp_client, file_tools, _, go_doc_tool = create_summary_agent(
        argot_mcp_path,
        model_config,
        str(out_dir),
        mcp_cwd=mcp_cwd,
        allowed_filename=out_file,
    )

    # Don't expose check_summary_valid to the agent — we call it ourselves after the agent
    # writes, and feed validation errors back as a follow-up prompt.
    agent_tools = allowed_tools - {"check_summary_valid"}

    with mcp_client:
        mcp_tools = mcp_client.list_tools_sync()
        filtered_mcp_tools = [t for t in mcp_tools if t.tool_name in agent_tools]

        all_tools = filtered_mcp_tools + file_tools.get_tools() + [go_doc_tool]

        agent = Agent(
            model=model,
            tools=all_tools,
            system_prompt=system_prompt,
        )

        func_list = format_spec_iterm(entry)
        out_file_abs = str(out_dir / out_file)

        prompt = f"""Generate dataflow summaries for the following Go program:

Config file(s): {", ".join(config_files)}
Target: {target}

Functions to summarize:
{func_list}

Follow the workflow:
0. Load the config using argot_reload_config by passing the config file
1. Load the program with argot_load using the config file(s) and target (provide the target argument, not paths)
2. For each function, gather context and generate a summary
3. Write the summaries to {out_file} with write_yaml_file, using exactly that filename
   (not a name based on the function/package).
   Include a YAML comment block at the top of the file (lines starting with #) explaining
   your reasoning: which flows you found, why you included or excluded each one, and any
   ambiguities. This comment is for human review and does not affect the parsed output.
   Then write the dataflow-summaries YAML below the comment.
"""
        await agent.invoke_async(prompt)

        # Validate and retry loop: call check_summary_valid ourselves and feed errors back.
        max_validation_attempts = 3
        for _ in range(max_validation_attempts):
            if not Path(out_file_abs).exists():
                break
            result = mcp_client.call_tool_sync(
                tool_use_id="validate",
                name="check_summary_valid",
                arguments={"path": out_file_abs},
            )
            text = "\n".join(item.get("text", "") for item in result.get("content", []))
            if "invalid" not in text.lower():
                break
            await agent.invoke_async(
                f"The summaries file {out_file} has validation problems:\n\n{text}\n\n"
                f"Please fix the issues and rewrite {out_file} with write_yaml_file."
            )


if __name__ == "__main__":
    sys.exit(main())
