#!/usr/bin/env python3
"""CLI for generating dataflow summaries."""

import argparse
import json
import sys
from typing import List, Any
import os
import logging
import yaml
from pathlib import Path

from summary_generator.agent import (
    create_summary_agent,
    generate_summaries,
    WORKFLOW_PROMPT,
)
from summary_generator.stats import compute_statistics, print_statistics
from strands import Agent
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry
from strands_tools import editor


os.environ["BYPASS_TOOL_CONSENT"] = "true"


class YAMLOnlyEditorHook(HookProvider):
    """Hook to restrict the editor tool to YAML files within a base directory.

    Without this, the editor tool's own commands have no path restriction at all (view/
    find_line ignore path and extension entirely; write commands only check the .yaml/.yml
    extension, not the path) -- so an agent could view or, worse, create/str_replace/
    pattern_replace/insert any YAML file anywhere on disk. This mirrors SafeFileTools'
    base_dir restriction so the editor tool can't be used to bypass it.
    """

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir).resolve()

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self.validate_editor_call)

    def validate_editor_call(self, event: BeforeToolCallEvent) -> None:
        if event.tool_use["name"] != "editor":
            return

        tool_input = event.tool_use.get("input", {})
        command = tool_input.get("command")
        path = tool_input.get("path", "")

        path_obj = Path(path).expanduser()
        resolved = path_obj if path_obj.is_absolute() else (self.base_dir / path_obj)
        resolved = resolved.resolve()
        try:
            resolved.relative_to(self.base_dir)
        except ValueError:
            event.cancel_tool = (
                f"Editor operations are restricted to {self.base_dir}. "
                f"Attempted path: {path}"
            )
            return

        if command not in ["view", "find_line"]:
            if path_obj.suffix not in [".yaml", ".yml"]:
                event.cancel_tool = f"Editor write operations are restricted to YAML files only. Attempted to write: {path}"


def load_functions_list(path: str) -> list[dict]:
    """Load function list from JSON or YAML file."""
    file_path = Path(path)
    with open(file_path) as f:
        if file_path.suffix in [".yaml", ".yml"]:
            return yaml.safe_load(f)
        else:
            return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Generate dataflow summaries using Strands Agents and Argot MCP",
        epilog="""
Available Bedrock models (as of July 2026):
  - anthropic.claude-sonnet-5 (recommended, default)
  - anthropic.claude-opus-5 (most capable)
  - anthropic.claude-haiku-4-5-20251001-v1:0 (fastest)

Note: Claude 4+ models use inference profiles automatically for better availability.

For other providers, use their model IDs:
  - Anthropic API: claude-sonnet-4-5, claude-haiku-4-5, claude-opus-4-5
  - Ollama: llama3, mistral, etc.
  - OpenAI: gpt-4, gpt-4-turbo, etc.
        """,
    )
    parser.add_argument(
        "--argot-mcp",
        required=False,
        # By default, argot users will have it on the path
        default="argot-mcp-server",
        help="Path to argot-mcp-server binary",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        help="Process functions in batches of this size (default: all at once)",
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
        help="Directory the agent may write summaries.yaml (and other .yaml/.yml files) to "
        "-- SafeFileTools/the editor tool restrict all agent file writes to this directory.",
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
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
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
        "--stats-json", help="Output file for statistics in JSON format"
    )
    parser.add_argument(
        "--target",
        default="main",
        help="Target name in config to analyze (default: main)",
    )

    args = parser.parse_args()

    # Check if argot-mcp-server exists
    import shutil

    argot_mcp_path = args.argot_mcp

    # Check if it's an absolute/relative path or just a command name
    if "/" in argot_mcp_path or "\\" in argot_mcp_path:
        # User specified a path
        if not Path(argot_mcp_path).exists():
            print(
                f"Error: argot-mcp-server not found at specified path: {argot_mcp_path}",
                file=sys.stderr,
            )
            print("Please check the path and try again.", file=sys.stderr)
            return 1
    else:
        # Check if it's on PATH
        if not shutil.which(argot_mcp_path):
            print(f"Error: '{argot_mcp_path}' not found on PATH", file=sys.stderr)
            print("", file=sys.stderr)
            print("To fix this:", file=sys.stderr)
            print(
                "  1. Run 'make mcp-install' from the repo root to install it, or",
                file=sys.stderr,
            )
            print(
                "  2. Specify the path with --argot-mcp /path/to/argot-mcp-server",
                file=sys.stderr,
            )
            return 1

    # Load function list
    try:
        functions = load_functions_list(args.functions)
    except Exception as e:
        print(f"Error loading functions list: {e}", file=sys.stderr)
        return 1

    # Get config directory and filenames (use first config file's directory)
    config_path = Path(args.config[0]).absolute()
    config_dir = config_path.parent

    # mcp_cwd = the config's own project-root, resolved the same way Go resolves it.
    with open(config_path) as f:
        loaded_config = yaml.safe_load(f) or {}
    project_root = (loaded_config.get("options") or {}).get("project-root", "")
    if not project_root:
        mcp_cwd = config_dir
    elif Path(project_root).is_absolute():
        mcp_cwd = Path(project_root)
    else:
        mcp_cwd = (config_dir / project_root).resolve()

    # Config paths relative to mcp_cwd, for the agent's argot_load/argot_reload_config calls.
    # relpath (not relative_to) since the config may live outside mcp_cwd's tree.
    config_files = [
        os.path.relpath(Path(c).absolute(), start=mcp_cwd) for c in args.config
    ]

    # out_dir: where the agent may write summaries.yaml. Deliberately separate from mcp_cwd
    # (the real repo checkout, never writable) and config_dir (may be a shared config).
    out_dir = Path(args.out_dir).absolute()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Configure model
    model_config = {
        "provider": args.provider,
        "model_id": args.model,
        "region": args.region,
        "inference_profile": args.inference_profile,
    }

    logging.getLogger("strands").setLevel(logging.INFO)
    log_out = "summary-generator.log"
    if args.output:
        log_out = args.output
    # Add a handler to see the logs
    logging.basicConfig(
        filename=log_out,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    # Create model and MCP client
    try:
        model, mcp_client, file_tools, prompt_tool, go_doc_tool = create_summary_agent(
            argot_mcp_path, model_config, str(out_dir), mcp_cwd=str(mcp_cwd)
        )
    except Exception as e:
        print(f"Error creating agent: {e}", file=sys.stderr)
        return 1

    # Generate summaries with MCP client context
    try:
        with mcp_client:
            # Create agent with tools inside context manager
            mcp_tools = mcp_client.list_tools_sync()
            # Filter to only tools mentioned in the workflow prompt
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
                    if tool_name.strip() not in allowed_tools:
                        print(
                            f"Warning: Unknown tool name '{tool_name.strip()}' in mask, ignoring",
                            file=sys.stderr,
                        )
                    allowed_tools.discard(tool_name.strip())
            filtered_mcp_tools = [t for t in mcp_tools if t.tool_name in allowed_tools]
            print(
                f"Available tools: {[t.tool_name for t in filtered_mcp_tools]}",
                file=sys.stderr,
            )

            all_tools = (
                filtered_mcp_tools
                + file_tools.get_tools()
                + [prompt_tool]
                + [go_doc_tool]
                + [editor.editor]
            )

            agent = Agent(
                model=model,
                tools=all_tools,
                system_prompt=WORKFLOW_PROMPT,
                hooks=[YAMLOnlyEditorHook(str(out_dir))],
            )

            result = generate_summaries(
                agent, config_files, args.target, functions, args.batch_size
            )
            print(result)
            stats = compute_statistics(log_out)
            print_statistics(stats)

            # Write stats to JSON if requested
            if args.stats_json:
                import json

                # Convert datetime objects to strings for JSON serialization
                stats_json = stats.copy()
                if "session" in stats_json:
                    stats_json["session"]["start"] = stats_json["session"][
                        "start"
                    ].isoformat()
                    stats_json["session"]["end"] = stats_json["session"][
                        "end"
                    ].isoformat()
                if "tools" in stats_json and "timeline" in stats_json["tools"]:
                    stats_json["tools"]["timeline"] = [
                        (ts.isoformat(), tool)
                        for ts, tool in stats_json["tools"]["timeline"]
                    ]

                with open(args.stats_json, "w") as f:
                    json.dump(stats_json, f, indent=2)
                print(f"Statistics written to {args.stats_json}", file=sys.stderr)

    except Exception as e:
        print(f"Error generating summaries: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
