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
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dependencies"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/cmd/argot/cli"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"golang.org/x/tools/go/ssa"
)

// jsonRpcVersion is the protocol version used by the server
const jsonRpcVersion = "2.0"

// paginationThreshold is the character limit before paginating responses
const paginationThreshold = 50000

// pageSize is the number of characters per page
const pageSize = 40000

// The error codes below are defined here: https://www.jsonrpc.org/specification#error_object

// codeParseError : -32700 	Invalid JSON was received by the server.
const codeParseError = -32700

// codeMethodNotFound : -32601 	Method not found 	The method does not exist / is not available.
const codeMethodNotFound = -32601

// codeInvalidParams : -32602 	Invalid params 	Invalid method parameter(s).
const codeInvalidParams = -32602

// codeInternalError : -32603 	Internal error 	Internal JSON-RPC error.
const codeInternalError = -32603

//go:embed dataflow-summary-generation-prompt.txt
var dataflowPrompt string

//go:embed config-generation-prompt.txt
var configPrompt string

//go:embed taint-tracking-definition-prompt.txt
var taintPrompt string

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

// toolCallParams is the structure used by the MCP protocol for all tool cals (tool name, tool arguments)
type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

var allowedCliTools = map[string]bool{
	cli.CmdAstName:        true,
	cli.CmdCalleesName:    true,
	cli.CmdCallersName:    true,
	cli.CmdLoadName:       true,
	cli.CmdListName:       true,
	cli.CmdFocusName:      true,
	cli.CmdMayAliasName:   true,
	cli.CmdPackageName:    true,
	cli.CmdRebuildName:    true,
	cli.CmdScanName:       true,
	cli.CmdMembersName:    true,
	cli.CmdRunPointerName: true,
	cli.CmdShowSsaName:    true,
	cli.CmdSrcName:        true,
	cli.CmdSsaInstrName:   true,
	cli.CmdSsaValueName:   true,
	cli.CmdStateName:      true,
	cli.CmdStatsName:      true,
	cli.CmdSummarizeName:  true,
	cli.CmdSummaryName:    true,
	cli.CmdUnfocusName:    true,
	cli.CmdCheckName:      true,
	cli.CmdReconfigName:   true,
}

/*
*
serverState is a struct that holds the state of the server. It is passed to all handlers and contains
the output of the commands and the tools that are available on the server. The serverState struct
contains the following fields:

- cmdOut: the output of the commands
- cmdErr: the error output of the commands
- outputter: the outputter used to write the output of the commands
- cliSession: the cli session used to execute the commands. Contains all state information relating to program analysis.
- tools: the tools that are available on the server
- paginationStore: stores pages for paginated responses
*/
type serverState struct {
	cmdOut          *bytes.Buffer
	cmdErr          *bytes.Buffer
	outputter       cli.Outputter
	cliSession      *cli.Session
	tools           map[string]cli.CommandDefinition
	paginationStore map[string][]string
}

/*
*
newState creates a new serverState struct and initializes the outputter and cliSession. The
outputter is used to write the output of the commands and the cliSession is used to execute the
commands.
*/
func newState(configPath string) *serverState {
	// We need error and regular output buffers to collect output of commands
	outputterOut := bytes.NewBuffer(nil)
	outputterErr := bytes.NewBuffer(nil)
	return &serverState{
		cmdOut:          outputterOut,
		cmdErr:          outputterErr,
		outputter:       cli.NewOutputter(outputterOut, outputterErr),
		cliSession:      cli.NewSession(tools.CommonFlags{ConfigPath: configPath}, false),
		tools:           make(map[string]cli.CommandDefinition),
		paginationStore: make(map[string][]string),
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	state := newState("")
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			state.sendError(req.ID, codeParseError, "Parse error")
			continue
		}

		switch req.Method {
		case "initialize":
			state.handleInitialize(req)
		case "tools/list":
			state.handleToolsList(req)
		case "tools/call":
			state.handleToolCall(req)
		case "prompts/list":
			state.handlePromptsList(req)
		case "prompts/get":
			state.handlePromptsGet(req)
		case "resources/list":
			state.handleResourcesList(req)
		case "resources/read":
			state.handleResourcesRead(req)
		case "notifications/initialized":
			state.handleInitialized(req)
		default:
			state.sendError(req.ID, codeMethodNotFound, fmt.Sprintf("Method %s not found", req.Method))
		}
	}
}

/*
*
handleInitialize is called when the client sends an initialize request. The server responds with a
serverInfo object that contains information about the server and the capabilities of the server. The
serverInfo object contains the following fields:

- protocolVersion: the version of the server
- capabilities: the capabilities of the server
- serverInfo: the name and version of the server
- instructions: instructions for the client on how to use the server
*/
func (s *serverState) handleInitialize(req jsonRPCRequest) {
	for commandName, tool := range cli.Commands {
		if allowedCliTools[commandName] {
			s.tools[tool.Name] = tool
		}

	}
	s.cliSession.LoadConfig(s.outputter, true)
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{
				"listChanged": true,
			},
			"prompts": map[string]interface{}{
				"listChanged": true,
			},
			"resources": map[string]interface{}{
				"listChanged": false,
			},
		},
		"serverInfo": map[string]interface{}{
			"name":    "argot-mcp-server",
			"version": "1.0.0",
		},
		"instructions": "argot-mcp-server is a Go language analysis tool. Most of the interactions" +
			"with the argot-mcp-server are stateful: you load a program to analyze, inspect this program," +
			"run additional analyses. You can show the source code of a function, show the SSA representation and" +
			"inspect specific values in the SSA representation. More advanced analyses such as taint and backtrace " +
			"analysis require loading a configuration file. Note: when loading a program, the main package will be" +
			"called command-line-arguments instead of main.",
	}
	s.sendResponse(req.ID, result)
}

/*
*
handleInitialized is called when the client sends a notifications/initialized request. The server
responds with an empty response.
*/
func (s *serverState) handleInitialized(req jsonRPCRequest) {
	// DO NOTHING
}

/*
*
handleToolsList is called when the client sends a tools/list request. The server responds with a
list of tools that are available on the server. The list of tools is a list of MCPTool objects. The
MCPTool object contains the following fields:

- name: the name of the tool
- description: a description of the tool
- inputSchema: the input schema of the tool
- outputSchema: the output schema of the tool, with type, properties and the required args.

Most of the tools are CLI tools defined in the cmd/argot/cli/defs.go
*/
func (s *serverState) handleToolsList(req jsonRPCRequest) {
	serverTools := []tools.MCPTool{
		{
			Name: "go_dependencies",
			Description: "Analyzes dependencies of a given Go package, and provides information about how much of each" +
				" dependency is used by the package being analyzed. For example, this can be used to identify " +
				"dependencies that have very little use in the code, and therefore could be eliminated.",
			InputSchema: tools.MCPInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
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
				Required: []string{"paths"},
			},
		},
	}
	for commandName, tool := range cli.Commands {
		if allowedCliTools[commandName] {
			serverTools = append(serverTools, tool.ToMCPToolDefinition())
		}
	}
	s.sendResponse(req.ID, map[string]interface{}{"tools": serverTools})
}

/*
*
handleToolCall is called when the client sends a tools/call request.
Effectively this is a dispatcher for all tool calls. It is responsible for calling the appropriate
handler for the tool call.
*/
func (s *serverState) handleToolCall(req jsonRPCRequest) {
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		s.sendError(req.ID, codeInvalidParams, "Invalid params")
		return
	}

	var toolCall toolCallParams
	paramBytes, _ := json.Marshal(params)
	if err := json.Unmarshal(paramBytes, &toolCall); err != nil {
		s.sendError(req.ID, codeInvalidParams, "Invalid tool call params")
		return
	}

	// dispatch depending on tool name
	switch toolCall.Name {
	case "go_dependencies":
		s.handleDependencies(req.ID, toolCall.Arguments)
	default:
		// Is this a CLI command?
		if command, ok := s.tools[toolCall.Name]; ok {
			s.handleCliCommand(req.ID, toolCall, command)
		} else {
			s.sendError(req.ID, codeMethodNotFound, fmt.Sprintf("Tool %s not found", toolCall.Name))
		}
	}
}

/*
*
handleCliCommand is a method that handles the "tools/call" JSON-RPC method for the CLI tools specifically.
It is responsible for running the CLI command and sending the response back to the client.
*/
func (s *serverState) handleCliCommand(id interface{},
	toolCall toolCallParams, command cli.CommandDefinition) {
	defer func() {
		s.cmdErr.Reset()
		s.cmdOut.Reset()
	}()

	// Recover from any panic caused by the command; we'd rather reinitialize the cli than crash
	// the MCP server.
	defer func() {
		if r := recover(); r != nil {
			s.cliSession = cli.NewSession(tools.CommonFlags{}, false)
			s.sendError(id, codeInternalError, fmt.Sprintf("internal panic, reinitialized session: %v", r))
		}
	}()

	// Capture stderr output on those commands, so that it doesn't interfere with the
	// MCP server's communication
	var buf bytes.Buffer
	// Save the original stderr
	originalStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	// Extract command name
	commandArgs, translationError := command.SchemaTranslation(toolCall.Arguments)
	if translationError != nil {
		s.sendError(id, codeInvalidParams, translationError.Error())
		return
	}
	// Run the command, catch any resulting panic
	command.Function(s.outputter, s.cliSession, commandArgs, false)

	// Restore the original stderr
	w.Close()
	os.Stderr = originalStderr
	_, err := io.Copy(&buf, r)
	if err != nil {
		s.sendError(id, codeInternalError, fmt.Sprintf("Error reading from pipe: %v\n", err))
		return
	}
	// Collect outputs
	stdErrs := buf.String()
	if stdErrs != "" {
		s.sendError(id, codeInternalError, stdErrs)
		return
	}
	errs := s.cmdErr.String()
	if errs != "" {
		s.sendError(id, codeInternalError, errs)
		return
	}

	// Check if cursor is provided for pagination
	if cursor, ok := toolCall.Arguments["cursor"].(string); ok {
		s.handlePaginatedResponse(id, cursor)
		return
	}

	output := s.cmdOut.String()
	// Check if output needs pagination
	if len(output) > paginationThreshold {
		s.sendPaginatedResponse(id, output)
	} else {
		s.sendResponse(id, map[string]interface{}{
			"content": []content{{Type: "text", Text: output}},
			"isError": false,
		})
	}
}

/*
*
handlePromptsList is a method that handles the "prompts/list" JSON-RPC method.
It is responsible for returning a list of available prompts.
*/
func (s *serverState) handlePromptsList(req jsonRPCRequest) {
	prompts := []map[string]interface{}{
		{
			"name":        "dataflow-summary-generation",
			"description": "Generate dataflow summaries for Go functions using Argot analysis tools",
		},
		{
			"name":        "config-generation",
			"description": "Generate Argot configuration files with targets and analysis options",
		},
		{
			"name":        "taint-tracking-definition",
			"description": "Generate taint tracking problem definitions for Go codebases using Argot",
		},
	}
	s.sendResponse(req.ID, map[string]interface{}{"prompts": prompts})
}

/*
*
handlePromptsGet is a method that handles the "prompts/get" JSON-RPC method.
It is responsible for returning the prompt with the given name.
*/
func (s *serverState) handlePromptsGet(req jsonRPCRequest) {
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		s.sendError(req.ID, codeInvalidParams, "Invalid params")
		return
	}

	name, ok := params["name"].(string)
	if !ok {
		s.sendError(req.ID, codeInvalidParams, "name parameter is required")
		return
	}

	switch name {
	case "dataflow-summary-generation":
		result := map[string]interface{}{
			"description": "Generate dataflow summaries for Go functions using Argot analysis tools",
			"messages": []map[string]interface{}{
				{
					"role": "user",
					"content": map[string]interface{}{
						"type": "text",
						"text": dataflowPrompt,
					},
				},
			},
		}
		s.sendResponse(req.ID, result)
	case "config-generation":
		result := map[string]interface{}{
			"description": "Generate Argot configuration files with targets and analysis options",
			"messages": []map[string]interface{}{
				{
					"role": "user",
					"content": map[string]interface{}{
						"type": "text",
						"text": configPrompt,
					},
				},
			},
		}
		s.sendResponse(req.ID, result)
	case "taint-tracking-definition":
		result := map[string]interface{}{
			"description": "Generate taint tracking problem definitions for Go codebases using Argot",
			"messages": []map[string]interface{}{
				{
					"role": "user",
					"content": map[string]interface{}{
						"type": "text",
						"text": taintPrompt,
					},
				},
			},
		}
		s.sendResponse(req.ID, result)
	default:
		s.sendError(req.ID, codeMethodNotFound, fmt.Sprintf("Prompt %s not found", name))
	}
}

/*
*
handleDependencies is a method that handles the "go_dependencies" tool call.
It is responsible for running the dependency analysis and sending the response back to the client.
*/
func (s *serverState) handleDependencies(id interface{}, args map[string]interface{}) {
	// Extract paths
	pathsInterface, ok := args["paths"]
	if !ok {
		s.sendError(id, codeInvalidParams, "paths parameter is required")
		return
	}
	pathsSlice, ok := pathsInterface.([]interface{})
	if !ok {
		s.sendError(id, codeInvalidParams, "paths must be an array")
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
		s.sendError(id, codeInternalError, fmt.Sprintf("Analysis failed: %v", err))
		return
	}

	s.sendResponse(id, map[string]interface{}{
		"content": []content{{Type: "text", Text: fmt.Sprintf("%+v", results)}},
		"isError": false,
	})
}

/*
*
runDependencyAnalysis is a method that runs the dependency analysis for the given paths.
It returns a slice of maps, each containing the analysis results for a target.
The analysis results include the target name, the dependencies, and any errors or logs.
*/
func runDependencyAnalysis(paths []string, locThreshold int, usageThreshold float64) ([]map[string]interface{}, error) {
	cfg := config.NewDefault()
	cfg.SummarizeOnDemand = true

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

func (s *serverState) sendResponse(id interface{}, result interface{}) {
	resp := jsonRPCResponse{
		JSONRPC: jsonRpcVersion,
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	fmt.Println(string(data))
}

func (s *serverState) sendError(id interface{}, code int, message string) {
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

func (s *serverState) sendPaginatedResponse(id interface{}, output string) {
	pages := s.splitIntoPages(output)
	if len(pages) == 0 {
		s.sendResponse(id, map[string]interface{}{
			"content": []content{{Type: "text", Text: ""}},
			"isError": false,
		})
		return
	}

	cursor := s.generateCursor()
	s.paginationStore[cursor] = pages[1:]

	result := map[string]interface{}{
		"content": []content{{Type: "text", Text: pages[0]}},
		"isError": false,
	}
	if len(pages) > 1 {
		result["nextCursor"] = cursor
	}
	s.sendResponse(id, result)
}

func (s *serverState) handlePaginatedResponse(id interface{}, cursor string) {
	pages, ok := s.paginationStore[cursor]
	if !ok {
		s.sendError(id, codeInvalidParams, "Invalid cursor")
		return
	}

	if len(pages) == 0 {
		delete(s.paginationStore, cursor)
		s.sendError(id, codeInvalidParams, "No more pages")
		return
	}

	result := map[string]interface{}{
		"content": []content{{Type: "text", Text: pages[0]}},
		"isError": false,
	}

	if len(pages) > 1 {
		s.paginationStore[cursor] = pages[1:]
		result["nextCursor"] = cursor
	} else {
		delete(s.paginationStore, cursor)
	}

	s.sendResponse(id, result)
}

func (s *serverState) splitIntoPages(output string) []string {
	if len(output) <= pageSize {
		return []string{output}
	}

	var pages []string
	lines := strings.Split(output, "\n")
	var currentPage strings.Builder

	for _, line := range lines {
		if currentPage.Len()+len(line)+1 > pageSize && currentPage.Len() > 0 {
			pages = append(pages, currentPage.String())
			currentPage.Reset()
		}
		if currentPage.Len() > 0 {
			currentPage.WriteString("\n")
		}
		currentPage.WriteString(line)
	}

	if currentPage.Len() > 0 {
		pages = append(pages, currentPage.String())
	}

	return pages
}

func (s *serverState) generateCursor() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", len(s.paginationStore))))
	return base64.URLEncoding.EncodeToString(hash[:16])
}
