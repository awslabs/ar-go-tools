# MCP Server

The MCP (Model Context Protocol) server exposes Argot's analysis tools through a standardized protocol for AI assistants and other clients.

## Installation

```bash
# Install globally
make mcp-install

# Or install directly with go
go install github.com/awslabs/ar-go-tools/cmd/argot-mcp-server@latest

# Run the server
argot-mcp-server
```

The server communicates via stdin/stdout using JSON-RPC 2.0.

## Available Tools

### go_dependencies

Analyzes Go package dependencies and reports usage statistics.

**Parameters:**
- `paths` (required): Array of Go package paths or source files
- `loc` (optional, default: 100): Minimum lines of code threshold for warnings  
- `usage` (optional, default: 10.0): Usage percentage threshold for warnings

**Example:**
```json
{
  "name": "go_dependencies",
  "arguments": {
    "paths": ["./main.go", "./pkg/..."],
    "loc": 50,
    "usage": 5.0
  }
}
```

## Testing

Run the test suite:
```bash
go test ./cmd/argot-mcp-server
```

## Configuration

To use the Argot MCP server with an AI assistant, add it to your MCP configuration file:

```json
{
  "mcpServers": {
    "argot": {
      "command": "argot-mcp-server",
      "args": []
    }
  }
}
```

The configuration file location depends on your client:
- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- **Other clients**: Check your client's documentation for the MCP configuration file location