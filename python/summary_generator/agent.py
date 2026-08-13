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

Follow the workflow in the dataflow summary generation instructions below. Key points:

- Use argot_show_src for functions in the loaded program. If it fails, use go_doc with
  src=true instead — do not retry argot_show_src with different patterns.
- Always use fully qualified package paths with go_doc (e.g. "text/template/parse.Tree.Parse").
- For pointer receivers, omit the star: "text/tabwriter.Writer.Write" (not "*Writer.Write").
- Don't waste context inspecting well-known stdlib functions whose behavior is obvious.
- Write the summary with write_yaml_file using exactly the filename given in the request.
- Include a YAML comment block (# lines) at the top explaining your reasoning.

Available file tools: list_files, read_file, write_yaml_file (restricted to output directory).
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


def create_summary_agent(argot_mcp_path: str, model_config: dict, out_dir: str, mcp_cwd: str, allowed_filename: str | None = None):
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
    
    file_tools = SafeFileTools(out_dir, allowed_filename=allowed_filename)

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


def entry_filename(entry: dict) -> str:
    """Derive a stable, filesystem-safe YAML filename from a summary entry.

    Examples: "fmt.Printf.yaml", "text_tabwriter.Writer.Write.yaml",
    "text_template_parse.Tree.Parse.yaml"
    """
    pkg = entry.get("package", "unknown")
    # Replace / with _ to keep full package path in the filename.
    pkg_safe = pkg.replace("/", "_")
    recv = entry.get("receiver") or entry.get("interface") or ""
    func = entry.get("function") or entry.get("method") or "unknown"
    # Strip pointer prefix (*Type -> Type)
    recv = recv.lstrip("*")
    if recv:
        name = f"{pkg_safe}.{recv}.{func}"
    else:
        name = f"{pkg_safe}.{func}"
    name = name.replace(" ", "_").replace("*", "")
    return f"{name}.yaml"
