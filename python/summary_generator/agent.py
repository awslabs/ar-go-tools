"""Strands agent for generating dataflow summaries."""

import sys
import time
from pathlib import Path
from mcp import stdio_client, StdioServerParameters
from strands import Agent
from strands.tools.mcp import MCPClient, MCPAgentTool
from summary_generator.file_tools import SafeFileTools, create_dataflow_prompt_tool, create_go_doc_tool


class CacheBustingMCPClient(MCPClient):
    """MCP Client that wraps tools to add cache-busting timestamps."""
    
    async def load_tools(self, **kwargs):
        """Load tools and wrap them with cache-busting."""
        tools = await super().load_tools(**kwargs)
        return [CacheBustingMCPTool(tool) for tool in tools]


class CacheBustingMCPTool(MCPAgentTool):
    """Wrapper that adds timestamp to tool calls to prevent caching."""
    
    def __init__(self, wrapped_tool):
        self._wrapped = wrapped_tool
    
    @property
    def tool_name(self):
        return self._wrapped.tool_name
    
    @property
    def tool_spec(self):
        spec = self._wrapped.tool_spec.copy()
        # Add optional _cache_bust parameter
        if 'input_schema' in spec:
            schema = spec['input_schema']
            if 'properties' not in schema:
                schema['properties'] = {}
            schema['properties']['_cache_bust'] = {
                'type': 'string',
                'description': 'Internal timestamp for cache busting'
            }
        return spec
    
    async def stream(self, **kwargs):
        """Add timestamp to bust prompt caching."""
        kwargs['_cache_bust'] = str(time.time())
        return await self._wrapped.stream(**kwargs)


WORKFLOW_PROMPT = """You are an expert at generating dataflow summaries for Go functions.

Your workflow:
1. Load the program using argot_load with the provided config file(s) and target name
2. Read the dataflow summary generation prompt using get_dataflow_summary_prompt to understand the format
3. For each function in the provided list:
   - Use `go doc <function>` to see the function signature and documentation.
   - Use `go doc -src <function>` to see the source code of the function.
   - Make sure the summary includes taint flows within all callees.
   - Generate a dataflow summary following the YAML format from the prompt
4. Write the summaries with write_yaml_file, using exactly the filename given in the request
   (not a name based on the function/package)

You have access to file operations:
- get_dataflow_summary_prompt: Get the dataflow summary generation instructions
- list_files: List files in a directory
- read_file: Read any text file
- write_yaml_file: Write YAML files (only .yaml/.yml extensions allowed)

All file operations are restricted to a dedicated output directory and its subdirectories (not the config file's own directory, and not the analyzed program's directory).

Include all possible flows in the summaries, but make sure to be as precise as possible. Only include a flow in the summary if you are reasonably sure it exists.

Use field-sensitive summaries whenever possible. The maximum access path length is 3: (e.g., a.b.c).
"""


def get_inference_profile(region: str, model_id: str) -> str:
    """Get an inference profile ARN for a model by querying AWS Bedrock.
    
    For Claude 4+ models that require inference profiles, this queries
    AWS to find an appropriate cross-region inference profile.
    
    Args:
        region: AWS region
        model_id: Model ID (e.g., anthropic.claude-sonnet-4-5-20250929-v1:0)
    
    Returns:
        Inference profile ID or model ID if no profile needed
    """
    try:
        import boto3
        
        # Check if model requires inference profile
        bedrock = boto3.client('bedrock', region_name=region)
        
        # Get model info
        try:
            profiles = bedrock.list_inference_profiles()
            for profile in profiles["inferenceProfileSummaries"]:
                for model in profile["models"]:
                    model_arn = model["modelArn"]
                    if model_arn.endswith(model_id) and region in model_arn:
                        inference_profile = profile["inferenceProfileArn"]                        
                        return inference_profile
                
        except Exception as e:
            print(f"Warning: Could not query model info: {e}", file=sys.stderr)
            
        # Fallback: return model ID as-is
        return model_id
        
    except ImportError:
        print("Warning: boto3 not available, using model ID directly", file=sys.stderr)
        return model_id
    except Exception as e:
        print(f"Warning: Error getting inference profile: {e}", file=sys.stderr)
        return model_id


def create_summary_agent(argot_mcp_path: str, model_config: dict, out_dir: str, mcp_cwd: str):
    """Create a Strands agent configured for summary generation.
    
    Args:
        argot_mcp_path: Path to the argot-mcp-server binary
        model_config: Dictionary with model configuration:
            - provider: "bedrock", "anthropic", "ollama", etc.
            - model_id: Model identifier
            - Additional provider-specific config
        out_dir: Directory the agent may write summaries.yaml to. SafeFileTools restricts
            all agent file writes here -- separate from mcp_cwd (the target repo, never
            writable) and from the config file's own directory.
        mcp_cwd: Working directory for the argot-mcp-server subprocess -- Go's package
            loading resolves target file paths relative to this, so it must be the target
            repo's own Go module.
    
    Returns:
        Model instance, MCPClient, SafeFileTools, prompt tool (for context management), and
        go doc tool
    """
    mcp_client = CacheBustingMCPClient(lambda: stdio_client(
        StdioServerParameters(
            command=argot_mcp_path,
            args=[],
            cwd=mcp_cwd
        )
    ))
    
    file_tools = SafeFileTools(out_dir)

    # Walk up from out_dir (not mcp_cwd, which is an external repo for everything but
    # sample) to find cmd/argot-mcp-server.
    repo_root = Path(out_dir).resolve()
    while repo_root != repo_root.parent:
        if (repo_root / "cmd" / "argot-mcp-server").exists():
            break
        repo_root = repo_root.parent
    
    prompt_tool = create_dataflow_prompt_tool(str(repo_root))

    # go doc must run from mcp_cwd (the target repo's own Go module), not out_dir -- same
    # reasoning as the MCP server subprocess above.
    go_doc_tool = create_go_doc_tool(mcp_cwd)
    
    # Select model based on provider
    provider = model_config.get("provider", "bedrock")
    model_id = model_config["model_id"]
    
    if provider == "bedrock":
        from strands.models import BedrockModel
        
        # Use inference profile if provided, otherwise auto-detect
        inference_profile = model_config.get("inference_profile")
        if not inference_profile:
            inference_profile = get_inference_profile(
                model_config.get("region", "us-east-1"),
                model_id
            )
        
        model = BedrockModel(
            model_id=inference_profile,
            region_name=model_config.get("region", "us-east-1")
        )
    elif provider == "anthropic":
        from strands.models import AnthropicModel
        model = AnthropicModel(model_id=model_id)
    elif provider == "ollama":
        from strands.models import OllamaModel
        model = OllamaModel(
            model_id=model_id,
            base_url=model_config.get("base_url", "http://localhost:11434")
        )
    elif provider == "openai":
        from strands.models import OpenAIModel
        model = OpenAIModel(model_id=model_id)
    else:
        raise ValueError(f"Unsupported provider: {provider}")
    
    return model, mcp_client, file_tools, prompt_tool, go_doc_tool


def format_spec_iterm(spec_item: dict) -> str: 
    """Format a single item from a tool specification."""
    if spec_item.get('receiver') or spec_item.get('interface'):
        recv = spec_item.get('receiver') or spec_item.get('interface')
        return f"- {spec_item.get('package')}.{recv}.{spec_item.get('function') or spec_item.get('method')}"    
    return f"- {spec_item.get('package')}.{spec_item.get('function') or spec_item.get('method')}"    

def generate_summaries(agent, config_paths: list[str], target: str, functions: list[dict], batch_size: int | None = None) -> str:
    """Generate dataflow summaries for a list of functions.
    
    Args:
        agent: Configured Strands Agent
        config_paths: List of Argot config file paths
        target: Target name in config to analyze
        functions: List of function specifications, each with:
            - package: Package name
            - function/method: Function or method name
            - receiver/interface: (optional) For methods or interfaces
        batch_size: Number of functions to process per batch (None = all at once)
    
    Returns:
        YAML string with all generated summaries
    """
    if batch_size is None or batch_size >= len(functions):
        # Process all at once
        return _generate_batch(agent, config_paths, target, functions, 1, None)
    
    # Process in batches
    all_summaries = []
    for i in range(0, len(functions), batch_size):
        batch = functions[i:i + batch_size]
        batch_num = i // batch_size + 1
        total_batches = (len(functions) + batch_size - 1) // batch_size
        
        print(f"Processing batch {batch_num}/{total_batches} ({len(batch)} functions)...", file=sys.stderr)
        
        # Provide previous summaries as context
        context = "\n".join(all_summaries) if all_summaries else None
        result = _generate_batch(agent, config_paths, target, batch, batch_num, context)
        all_summaries.append(result)
    
    return "\n".join(all_summaries)


def _generate_batch(
    agent, config_paths: list[str], target: str, functions: list[dict],
    batch_num: int, previous_context: str | None = None,
) -> str:
    """Generate summaries for a single batch of functions."""
    func_list = "\n".join([format_spec_iterm(f) for f in functions])
    out_file = f"summaries-{batch_num:04d}.yaml"
    
    context_section = ""
    if previous_context:
        context_section = f"""
Previously generated summaries (for context):
```yaml
{previous_context}
```

"""
    
    prompt = f"""Generate dataflow summaries for the following Go program:

Config file(s): {', '.join(config_paths)}
Target: {target}

{context_section}Functions to summarize:
{func_list}

Follow the workflow:
0. Load the config using argot_reload_config by passing the config file 
1. Load the program with argot_load using the config file(s) and target (provide the target argument, not paths)
2. For each function, gather context and generate a summary
3. Write the summaries to {out_file} with write_yaml_file, using exactly that filename
   (not a name based on the function/package). Output the same YAML document as your response.
"""
    return str(agent(prompt))
