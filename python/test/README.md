# Test Directory

This directory contains a complete example setup for testing the summary generator.

## Contents

- `testprog/` - A simple Go program with various function patterns
  - `testprog.go` - Example functions including a taint analysis scenario
  - `config.yaml` - Argot configuration defining a taint tracking problem
  - `go.mod` - Go module definition
- `functions.json` - List of functions to generate summaries for

## Taint Analysis Example

The test program includes a taint tracking scenario:

**Source**: `GetUserInput()` - Returns sensitive user data
**Sink**: `LogPublicly(data)` - Logs data publicly (should not receive sensitive data)
**Sanitizer**: `Sanitize(data)` - Removes sensitive information

The `main()` function demonstrates:
1. A taint flow violation: `GetUserInput() → LogPublicly()` (should be detected)
2. A safe flow: `GetUserInput() → Sanitize() → LogPublicly()` (sanitized, no violation)

You can verify the taint analysis works:
```bash
cd testprog
argot taint -config config.yaml .
```

## Running the Test

**Prerequisites:**
- Built `argot-mcp-server` on your PATH (run `make mcp-install` from repo root)
- Python virtual environment set up (see `../README.md`)

1. Set up Python environment (if not already done):
```bash
cd ../../python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Run the summary generator:
```bash
# Using AWS Bedrock (default) - set AWS_PROFILE if needed
AWS_PROFILE=my-profile python -m summary_generator.generate \
  --config ./test/testprog/config.yaml \
  --target main \
  --functions ./test/functions.json \
  --output ./test/output_summaries.yaml

# Or using local Ollama
python -m summary_generator.generate \
  --config ./test/testprog/config.yaml \
  --target main \
  --functions ./test/functions.json \
  --provider ollama \
  --model llama3 \
  --output ./test/output_summaries.yaml
```

## Expected Output

The tool should generate a YAML file with dataflow summaries for each function in `functions.json`. Each summary will be validated by `argot_check` before being included in the output.

## Test Functions

The test program includes:
- **SimpleFunction**: Basic argument-to-return flow
- **DataProcessor.Process**: Flow through struct fields
- **ReadAndTransform**: Flow from interface parameter
- **MultipleReturns**: Flow to multiple return values
