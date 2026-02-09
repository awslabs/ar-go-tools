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

from summary_generator.agent import create_summary_agent, generate_summaries, WORKFLOW_PROMPT
from summary_generator.stats import compute_statistics, print_statistics
from strands import Agent
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry
from strands_tools import editor


os.environ["BYPASS_TOOL_CONSENT"] = "true"




class YAMLOnlyEditorHook(HookProvider):
    """Hook to restrict editor tool to only write YAML files."""
    
    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self.validate_editor_write)
    
    def validate_editor_write(self, event: BeforeToolCallEvent) -> None:
        if event.tool_use["name"] != "editor":
            return
        
        tool_input = event.tool_use.get("input", {})
        command = tool_input.get("command")
        path = tool_input.get("path", "")
        
        if command not in ["view", "find_line"]:
            path_obj = Path(path)
            if path_obj.suffix not in [".yaml", ".yml"]:
                event.cancel_tool = f"Editor write operations are restricted to YAML files only. Attempted to write: {path}"



def load_functions_list(path: str) -> list[dict]:
    """Load function list from JSON or YAML file."""
    file_path = Path(path)
    with open(file_path) as f:
        if file_path.suffix in ['.yaml', '.yml']:
            return yaml.safe_load(f)
        else:
            return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Generate dataflow summaries using Strands Agents and Argot MCP",
        epilog="""
Available Bedrock models (as of Jan 2026):
  - anthropic.claude-sonnet-4-5-20250929-v1:0 (recommended, default)
  - anthropic.claude-haiku-4-5-20251001-v1:0 (fastest)
  - anthropic.claude-opus-4-5-20251101-v1:0 (most capable)

Note: Claude 4+ models use inference profiles automatically for better availability.

For other providers, use their model IDs:
  - Anthropic API: claude-sonnet-4-5, claude-haiku-4-5, claude-opus-4-5
  - Ollama: llama3, mistral, etc.
  - OpenAI: gpt-4, gpt-4-turbo, etc.
        """
    )
    parser.add_argument(
        "--argot-mcp",
        required=False,
        # By default, argot users will have it on the path
        default="argot-mcp-server",
        help="Path to argot-mcp-server binary"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        help="Process functions in batches of this size (default: all at once)"
    )
    parser.add_argument(
        "--config",
        required=True,
        nargs="+",
        help="Argot config file(s) for the program to analyze"
    )
    parser.add_argument(
        "--functions",
        required=True,
        help="JSON/YAML file with list of functions to summarize"
    )
    parser.add_argument(
        "--inference-profile",
        help="AWS Bedrock inference profile ARN (auto-detected if not specified)"
    )
    parser.add_argument(
        "--mask",
        default="",
        help="Mask for disallowed tools (comma-separated list of tool names)"
    )
    parser.add_argument(
        "--model",
        default="anthropic.claude-sonnet-4-5-20250929-v1:0",
        help="Model ID (default: Claude Sonnet 4.5 for Bedrock)"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--provider",
        default="bedrock",
        choices=["bedrock", "anthropic", "ollama", "openai"],
        help="LLM provider"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (for Bedrock)"
    )
    parser.add_argument(
        "--target",
        default="main",
        help="Target name in config to analyze (default: main)"
    )
    
    args = parser.parse_args()
    
    # Check if argot-mcp-server exists
    import shutil
    argot_mcp_path = args.argot_mcp
    
    # Check if it's an absolute/relative path or just a command name
    if '/' in argot_mcp_path or '\\' in argot_mcp_path:
        # User specified a path
        if not Path(argot_mcp_path).exists():
            print(f"Error: argot-mcp-server not found at specified path: {argot_mcp_path}", file=sys.stderr)
            print("Please check the path and try again.", file=sys.stderr)
            return 1
    else:
        # Check if it's on PATH
        if not shutil.which(argot_mcp_path):
            print(f"Error: '{argot_mcp_path}' not found on PATH", file=sys.stderr)
            print("", file=sys.stderr)
            print("To fix this:", file=sys.stderr)
            print("  1. Run 'make mcp-install' from the repo root to install it, or", file=sys.stderr)
            print("  2. Specify the path with --argot-mcp /path/to/argot-mcp-server", file=sys.stderr)
            return 1
    
    # Load function list
    try:
        functions = load_functions_list(args.functions)
    except Exception as e:
        print(f"Error loading functions list: {e}", file=sys.stderr)
        return 1
    
    # Get config directory and filenames (use first config file's directory)
    config_path = Path(args.config[0]).absolute()
    config_dir = str(config_path.parent)
    # Convert config paths to relative paths from config directory
    config_files = [Path(c).absolute().relative_to(config_path.parent).as_posix() for c in args.config]
    
    # Configure model
    model_config = {
        "provider": args.provider,
        "model_id": args.model,
        "region": args.region,
        "inference_profile": args.inference_profile
    }


    logging.getLogger("strands").setLevel(logging.DEBUG)
    log_out = 'summary-generator.log'
    if args.output:
        log_out = args.output
    # Add a handler to see the logs
    logging.basicConfig(
        filename=log_out,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",        
    )
    
    # Create model and MCP client
    try:
        model, mcp_client, file_tools, prompt_tool = create_summary_agent(argot_mcp_path, model_config, config_dir)
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
                "argot_run_pointer",                
                "argot_show_callees",
                "argot_dataflow_check"
            }
            if args.mask:
                for tool_name in args.mask.split(','):
                    if tool_name.strip() not in allowed_tools:
                        print(f"Warning: Unknown tool name '{tool_name.strip()}' in mask, ignoring", file=sys.stderr)
                    allowed_tools.discard(tool_name.strip())
            filtered_mcp_tools = [t for t in mcp_tools if t.tool_name in allowed_tools]
            print(f"Available tools: {[t.tool_name for t in filtered_mcp_tools]}", file=sys.stderr)
            
            all_tools = filtered_mcp_tools + file_tools.get_tools() + [prompt_tool] + [editor.editor]

            
            agent = Agent(
                model=model,
                tools=all_tools,
                system_prompt=WORKFLOW_PROMPT,
                hooks=[YAMLOnlyEditorHook()],
            )
            
            result = generate_summaries(agent, config_files, args.target, functions, args.batch_size)
            print(result)
            stats = compute_statistics(log_out)
            print_statistics(stats)

                
    except Exception as e:
        print(f"Error generating summaries: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
