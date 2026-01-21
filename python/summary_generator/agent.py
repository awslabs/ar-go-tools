"""Strands agent for generating dataflow summaries."""

import sys
import time
from pathlib import Path
from mcp import stdio_client, StdioServerParameters
from strands import Agent
from strands.tools.mcp import MCPClient, MCPAgentTool
from summary_generator.file_tools import SafeFileTools, create_dataflow_prompt_tool


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
   - Use argot_info to get the function signature and details
   - Use argot_ssa to see the SSA form of the function
   - Use argot_callees to understand what functions it calls (if relevant)
   - Generate a dataflow summary following the YAML format from the prompt
   - Use argot_check to validate the summary
   - If validation fails, analyze the error and revise the summary
   - Retry validation until it passes
4. Collect all validated summaries and output them as a single YAML document

You have access to file operations:
- get_dataflow_summary_prompt: Get the dataflow summary generation instructions
- list_files: List files in a directory
- read_file: Read any text file
- write_yaml_file: Write YAML files (only .yaml/.yml extensions allowed)

All file operations are restricted to the config directory and its subdirectories.

Be thorough and conservative in your analysis - include all possible data flows to ensure soundness.
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


def create_summary_agent(argot_mcp_path: str, model_config: dict, config_dir: str):
    """Create a Strands agent configured for summary generation.
    
    Args:
        argot_mcp_path: Path to the argot-mcp-server binary
        model_config: Dictionary with model configuration:
            - provider: "bedrock", "anthropic", "ollama", etc.
            - model_id: Model identifier
            - Additional provider-specific config
        config_dir: Directory containing the Argot config file (MCP server will run from here)
    
    Returns:
        Model instance, MCPClient, SafeFileTools, and prompt tool (for context management)
    """
    # Create MCP client for Argot tools
    # Start the MCP server in the config directory
    mcp_client = CacheBustingMCPClient(lambda: stdio_client(
        StdioServerParameters(
            command=argot_mcp_path,
            args=[],
            cwd=config_dir
        )
    ))
    
    # Create safe file tools restricted to config directory
    file_tools = SafeFileTools(config_dir)
    
    # Find repository root (go up from config_dir until we find cmd/argot-mcp-server)
    repo_root = Path(config_dir).resolve()
    while repo_root != repo_root.parent:
        if (repo_root / "cmd" / "argot-mcp-server").exists():
            break
        repo_root = repo_root.parent
    
    # Create dataflow prompt tool
    prompt_tool = create_dataflow_prompt_tool(str(repo_root))
    
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
    
    return model, mcp_client, file_tools, prompt_tool


def generate_summaries(agent, config_paths: list[str], target: str, functions: list[dict]) -> str:
    """Generate dataflow summaries for a list of functions.
    
    Args:
        agent: Configured Strands Agent
        config_paths: List of Argot config file paths
        target: Target name in config to analyze
        functions: List of function specifications, each with:
            - package: Package name
            - function/method: Function or method name
            - receiver/interface: (optional) For methods
    
    Returns:
        YAML string with all generated summaries
    """
    # Format function list for the agent
    func_list = "\n".join([
        f"- {f.get('package')}.{f.get('function') or f.get('method')}"
        for f in functions
    ])
    
    prompt = f"""Generate dataflow summaries for the following Go program:

Config file(s): {', '.join(config_paths)}
Target: {target}

Functions to summarize:
{func_list}

Follow the workflow:
0. Load the config using argot_reload_config by passing the config file 
1. Load the program with argot_load using the config file(s) and target (provide the target argument, not paths)
2. For each function, gather context and generate a summary
3. Validate each summary with argot_check and revise if needed
4. Output all validated summaries as a single YAML document
"""
    result = agent(prompt)
    return result
