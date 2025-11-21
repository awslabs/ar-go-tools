// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dependencies"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"golang.org/x/tools/go/ssa"
)

// jsonRpcVersion is the protocol version used by the server
const jsonRpcVersion = "2.0"

// The error codes below are defined here: https://www.jsonrpc.org/specification#error_object

// codeParseError : -32700 	Invalid JSON was received by the server.
const codeParseError = -32700

// codeMethodNotFound : -32601 	Method not found 	The method does not exist / is not available.
const codeMethodNotFound = -32601

// codeInvalidParams : -32602 	Invalid params 	Invalid method parameter(s).
const codeInvalidParams = -32602

// codeInternalError : -32603 	Internal error 	Internal JSON-RPC error.
const codeInternalError = -32603

// jsonRPCRequest is plain struct representing a request sent to the server
type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// jsonRPCResponse is a plain struct representing a response returned by the server
type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

// tool is the simple struct returned in the result of a response for a tool description request
type tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// toolCallParams is the structure used by the MCP protocol for all tool cals (tool name, tool arguments)
type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			sendError(req.ID, codeParseError, "Parse error")
			continue
		}

		switch req.Method {
		case "initialize":
			handleInitialize(req)
		case "tools/list":
			handleToolsList(req)
		case "tools/call":
			handleToolCall(req)
		default:
			sendError(req.ID, codeMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method))
		}
	}
}

func handleInitialize(req jsonRPCRequest) {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "argot-mcp-server",
			"version": "1.0.0",
		},
	}
	sendResponse(req.ID, result)
}

func handleToolsList(req jsonRPCRequest) {
	serverTools := []tool{
		{
			Name:        "go_dependencies",
			Description: "Analyzes dependencies of a given Go package, and provides information about how much of each dependency is used by the package being analyzed. For example, this can be used to identify dependencies that have very little use in the code, and therefore could be eliminated.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"paths": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Go package paths or source files to analyze.",
					},
					"loc": map[string]interface{}{
						"type":        "integer",
						"default":     100,
						"description": "Minimum lines of code threshold for warnings",
					},
					"usage": map[string]interface{}{
						"type":        "number",
						"default":     10.0,
						"description": "Usage percentage threshold for warnings",
					},
				},
				"required": []string{"paths"},
			},
		},
	}
	sendResponse(req.ID, map[string]interface{}{"serverTools": serverTools})
}

func handleToolCall(req jsonRPCRequest) {
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		sendError(req.ID, -32602, "Invalid params")
		return
	}

	var toolCall toolCallParams
	paramBytes, _ := json.Marshal(params)
	if err := json.Unmarshal(paramBytes, &toolCall); err != nil {
		sendError(req.ID, codeInvalidParams, "Invalid tool call params")
		return
	}

	switch toolCall.Name {
	case "go_dependencies":
		handleDependencies(req.ID, toolCall.Arguments)
	default:
		sendError(req.ID, codeMethodNotFound, "Tool not found")
	}
}

func handleDependencies(id interface{}, args map[string]interface{}) {
	// Extract paths
	pathsInterface, ok := args["paths"]
	if !ok {
		sendError(id, codeInvalidParams, "paths parameter is required")
		return
	}
	pathsSlice, ok := pathsInterface.([]interface{})
	if !ok {
		sendError(id, codeInvalidParams, "paths must be an array")
		return
	}
	paths := make([]string, len(pathsSlice))
	for i, p := range pathsSlice {
		paths[i] = p.(string)
	}

	// Extract optional parameters
	locThreshold := 100
	if loc, exists := args["loc"]; exists {
		if locFloat, ok := loc.(float64); ok {
			locThreshold = int(locFloat)
		}
	}

	usageThreshold := 10.0
	if usage, exists := args["usage"]; exists {
		if usageFloat, ok := usage.(float64); ok {
			usageThreshold = usageFloat
		}
	}

	// Run the analysis
	results, err := runDependencyAnalysis(paths, locThreshold, usageThreshold)
	if err != nil {
		sendError(id, codeInternalError, fmt.Sprintf("Analysis failed: %v", err))
		return
	}

	sendResponse(id, map[string]interface{}{
		"content": []content{{Type: "text", Text: fmt.Sprintf("%+v", results)}},
	})
}

func runDependencyAnalysis(paths []string, locThreshold int, usageThreshold float64) ([]map[string]interface{}, error) {
	cfg := config.NewDefault()

	actualTargets, err := tools.GetTargets(cfg, tools.TargetReqs{
		CmdlineArgs: paths,
		Tool:        config.DependenciesTool,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get targets: %v", err)
	}

	var results []map[string]interface{}
	for targetName, target := range actualTargets {
		// Create a new buffer for each target
		var errorBuffer bytes.Buffer

		loadOptions := config.LoadOptions{
			Platform:      target.Platform,
			PackageConfig: nil,
			BuildMode:     ssa.InstantiateGenerics,
			LoadTests:     false,
			ApplyRewrites: true,
		}

		cfgState := config.NewState(cfg, targetName, target.Patterns, loadOptions)
		cfgState.Logger.SetAllOutput(io.Discard)
		cfgState.Logger.SetError(&errorBuffer)

		state, err := loadprogram.NewState(cfgState).Value()
		if err != nil {
			result := map[string]interface{}{
				"target":       targetName,
				"dependencies": nil,
				"error":        err.Error(),
			}
			if errorBuffer.Len() > 0 {
				result["logs"] = errorBuffer.String()
			}
			results = append(results, result)
			continue
		}

		_, dependencyMap := dependencies.DependencyAnalysis(state, dependencies.DependencyConfigs{
			JsonFlag:       false,
			IncludeStdlib:  false,
			CoverageFile:   nil,
			CsvFile:        nil,
			UsageThreshold: usageThreshold,
			LocThreshold:   locThreshold,
			ComputeGraph:   false,
		})

		var deps []map[string]interface{}
		for name, entry := range dependencyMap {
			total := entry.ReachableLocs + entry.UnreachableLocs
			percentage := (100.0 * float64(entry.ReachableLocs)) / float64(total)
			needsWarning := !entry.IsIndirect && (int(entry.ReachableLocs) < locThreshold && percentage < usageThreshold)

			dep := map[string]interface{}{
				"name":           name,
				"direct":         !entry.IsIndirect,
				"reachable_locs": entry.ReachableLocs,
				"total_locs":     total,
				"usage_percent":  percentage,
				"needs_warning":  needsWarning,
			}
			if needsWarning {
				dep["warning_reason"] = fmt.Sprintf("less than %d lines used, and below %.1f%% usage",
					locThreshold, usageThreshold)
			}
			deps = append(deps, dep)
		}

		result := map[string]interface{}{
			"target":       targetName,
			"dependencies": deps,
		}

		// Only include logs field if there are actual logs
		if errorBuffer.Len() > 0 {
			result["logs"] = errorBuffer.String()
		}

		results = append(results, result)
	}

	return results, nil
}

func sendResponse(id interface{}, result interface{}) {
	resp := jsonRPCResponse{
		JSONRPC: jsonRpcVersion,
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	fmt.Println(string(data))
}

func sendError(id interface{}, code int, message string) {
	niceId := id
	if id == nil {
		niceId = 0
	}
	resp := jsonRPCResponse{
		JSONRPC: jsonRpcVersion,
		ID:      niceId,
		Error: map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
	data, _ := json.Marshal(resp)
	fmt.Println(string(data))
}
