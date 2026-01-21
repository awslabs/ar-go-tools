# Python Tools for Argot

Optional Python-based tooling for Argot analysis workflows.

## Setup

Create a virtual environment and install dependencies:

```bash
cd python
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Tools

### Summary Generator

Automated dataflow summary generation using Strands Agents SDK and the Argot MCP server.

See [summary_generator/README.md](summary_generator/README.md) for details.

## Testing

The `test/` directory contains a complete example with a test Go program and function list.

**Prerequisites:**
- Built `argot-mcp-server` binary on your PATH (run `make mcp-install` from repo root)
- Python virtual environment with dependencies installed

Use it to verify your setup:

```bash
source venv/bin/activate
python -m summary_generator.generate \
  --config ./test/testprog/config.yaml \
  --target main \
  --functions ./test/functions.json \
  --provider ollama \
  --model llama3 \
  --output ./test/output_summaries.yaml
```

```bash
source venv/bin/activate
python -m summary_generator.generate \
  --config ./test/testprog \
  --functions ./test/functions.json \
  --provider ollama \
  --model llama3 \
  --output ./test/output_summaries.yaml
```

See [test/README.md](test/README.md) for more details.

## Deactivating

When done:

```bash
deactivate
```
