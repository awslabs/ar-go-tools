# Dataflow Summary Generator

Automated generation of dataflow summaries for Go functions using Strands Agents SDK and the Argot MCP server.

## How It Works

1. Connects to the Argot MCP server to access analysis tools
2. Uses a Strands Agent with your choice of LLM to orchestrate the workflow
3. For each function, the agent:
   - Loads the program
   - Gathers context about the function
   - Generates a dataflow summary
   - Validates it with `argot_check`
   - Retries if validation fails
4. Outputs all summaries as YAML

## Prerequisites

- Built `argot-mcp-server` binary (see `cmd/argot-mcp-server/`)
  - Either on your PATH (run `make mcp-install` from repo root)
  - Or specify path with `--argot-mcp`
- Python virtual environment with dependencies installed (see `../README.md`)
- Access to an LLM provider (AWS Bedrock, Anthropic, Ollama, etc.)

## Usage

### 1. Create a functions list file

Create a JSON or YAML file listing functions to summarize:

```json
[
  {
    "package": "os",
    "function": "Open"
  },
  {
    "package": "io",
    "interface": "Reader",
    "method": "Read"
  },
  {
    "package": "mypackage",
    "receiver": "*MyStruct",
    "method": "Process"
  }
]
```

### 2. Create an Argot config file

Create a config.yaml with at least one target:

```yaml
targets:
  - name: main
    package: github.com/example/myproject
```

### 3. Run the generator

```bash
# Using AWS Bedrock (default)
python -m summary_generator.generate \
  --config config.yaml \
  --target main \
  --functions functions.json \
  --output summaries.yaml

# Process in batches of 10 (useful for large function lists)
python -m summary_generator.generate \
  --config config.yaml \
  --target main \
  --functions functions.json \
  --batch-size 10 \
  --output summaries.yaml

# With specific AWS profile (via environment)
AWS_PROFILE=my-profile python -m summary_generator.generate \
  --config config.yaml \
  --target main \
  --functions functions.json \
  --output summaries.yaml

# Using local Ollama
python -m summary_generator.generate \
  --config config.yaml \
  --target main \
  --functions functions.json \
  --provider ollama \
  --model llama3 \
  --output summaries.yaml

# Using Anthropic API
python -m summary_generator.generate \
  --config config.yaml \
  --functions functions.json \
  --provider anthropic \
  --model claude-sonnet-4-5 \
  --output summaries.yaml
```

**Note:** If `argot-mcp-server` is not on your PATH, specify it with `--argot-mcp /path/to/argot-mcp-server`.

## Configuration

### Batch Processing

For large function lists, use `--batch-size` to process functions in smaller groups:
- Each batch is processed sequentially
- Previous summaries are provided as context to subsequent batches
- Progress is shown: "Processing batch 1/5 (10 functions)..."
- Recommended batch size: 10-20 functions depending on complexity

### LLM Providers

**AWS Bedrock** (default):
- Requires AWS credentials configured (via environment variables or `~/.aws/credentials`)
- Use `AWS_PROFILE` environment variable to specify a profile
- Set `--region` if not using us-east-1
- Inference profiles are auto-detected for Claude 4+ models
- Model IDs: `anthropic.claude-sonnet-4-5-20250929-v1:0` (default), `anthropic.claude-haiku-4-5-20251001-v1:0`, `anthropic.claude-opus-4-5-20251101-v1:0`

**Anthropic**:
- Requires `ANTHROPIC_API_KEY` environment variable
- Model IDs: `claude-3-5-sonnet-20241022`, etc.

**Ollama** (local):
- Requires Ollama running locally
- Model IDs: `llama3`, `mistral`, etc.

**OpenAI**:
- Requires `OPENAI_API_KEY` environment variable
- Model IDs: `gpt-4`, `gpt-4-turbo`, etc.

## Example

See the `test/` directory for a complete working example with a test Go program.

```bash
# Quick test with the included example
cd python
source venv/bin/activate

# Ensure argot-mcp-server is installed
# (run 'make mcp-install' from repo root if needed)

# Run on test program
python -m summary_generator.generate \
  --config ./test/testprog/config.yaml \
  --target main \
  --functions ./test/functions.json \
  --output ./test/output_summaries.yaml
```

## Troubleshooting

**MCP connection errors**: Ensure `argot-mcp-server` is on your PATH or specify with `--argot-mcp`

**Model access errors**: Check your credentials and API keys are configured

**Validation failures**: The agent will retry, but persistent failures may indicate complex functions that need manual review
