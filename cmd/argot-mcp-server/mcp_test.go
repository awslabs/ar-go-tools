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
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// TestMCPServer is one big test that calls the tools in the mcp server.
// Server is started once at the beginning, then tools are tested through stdin/stdout interaction.
func TestMCPServer(t *testing.T) {
	// We need to start running the MCP server in a separate process.
	// We will send command on stdin and read from stdout
	cmd := exec.Command("go", "run", "main.go")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	scanner := bufio.NewScanner(stdout)

	// Test initialize
	initReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test", "version": "1.0.0"},
		},
	}
	sendRequest(t, stdin, initReq)
	response := readResponse(t, scanner)
	var initResp jsonRPCResponse
	if err := json.Unmarshal([]byte(response), &initResp); err != nil {
		t.Fatal(err)
	}
	if initResp.Error != nil {
		t.Fatalf("Initialize failed: %v", initResp.Error)
	}

	// Test tools list
	toolsReq := jsonRPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list", Params: map[string]interface{}{}}
	sendRequest(t, stdin, toolsReq)
	toolsListResponseCheck(t, readResponse(t, scanner))

	// Test valid dependencies call
	depsReq := jsonRPCRequest{
		JSONRPC: jsonRpcVersion,
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "go_dependencies",
			"arguments": map[string]interface{}{
				"paths": []string{"./testdata/sample.go"},
				"loc":   50,
				"usage": 5.0,
			},
		},
	}
	sendRequest(t, stdin, depsReq)
	response = readResponse(t, scanner)
	var depsResp jsonRPCResponse
	if err := json.Unmarshal([]byte(response), &depsResp); err != nil {
		t.Fatal(err)
	}
	if depsResp.Error != nil {
		t.Fatalf("Dependencies analysis failed: %v", depsResp.Error)
	}

	// Test invalid method
	invalidReq := jsonRPCRequest{JSONRPC: jsonRpcVersion, ID: 4, Method: "invalid/method"}
	sendRequest(t, stdin, invalidReq)
	response = readResponse(t, scanner)
	var invalidResp jsonRPCResponse
	json.Unmarshal([]byte(response), &invalidResp)
	if invalidResp.Error == nil {
		t.Error("Expected error for invalid method")
	}

	// Test missing paths parameter
	missingParamsReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "go_dependencies",
			"arguments": map[string]interface{}{},
		},
	}
	sendRequest(t, stdin, missingParamsReq)
	response = readResponse(t, scanner)
	var missingResp jsonRPCResponse
	json.Unmarshal([]byte(response), &missingResp)
	if missingResp.Error == nil {
		t.Error("Expected error for missing paths")
	}

	// Test unknown tool
	unknownToolReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "unknown_tool",
			"arguments": map[string]interface{}{},
		},
	}
	sendRequest(t, stdin, unknownToolReq)
	response = readResponse(t, scanner)
	var unknownResp jsonRPCResponse
	json.Unmarshal([]byte(response), &unknownResp)
	if unknownResp.Error == nil {
		t.Error("Expected error for unknown tool")
	}

	// Check load program
	checkLoadProgramTool(t, stdin, scanner)
	// Check list tools after load program
	checkListTool(t, stdin, scanner)
}

func sendRequest(t *testing.T, stdin io.WriteCloser, req jsonRPCRequest) {
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("S --> %s", data)
	stdin.Write(data)
	stdin.Write([]byte("\n"))
}

func readResponse(t *testing.T, scanner *bufio.Scanner) string {
	for scanner.Scan() {
		line := scanner.Text()
		t.Logf("R <-- %s", line)
		if strings.HasPrefix(line, "{") {
			return line
		}
	}
	t.Logf("No reponse")
	return ""
}

func toolsListResponseCheck(t *testing.T, response string) {
	if !strings.Contains(response, "go_dependencies") {
		t.Error("Expected go_dependencies tool in tools list")
	}
	// Deserialize JSON
	var resp jsonRPCResponse
	if err := json.Unmarshal([]byte(response), &resp); err != nil {
		t.Fatal(err)
	}
	// Check if the response is valid
	if resp.Error != nil {
		t.Fatalf("Tools list failed: %v", resp.Error)
	}
	// Check if the response contains the expected tools list
	toolsList, ok := resp.Result.(map[string]interface{})["tools"].([]interface{})
	if !ok {
		t.Fatal("Expected tools list in response")
	}
	for _, tool := range toolsList {
		mcpTool, ok := tool.(map[string]interface{})
		if !ok {
			t.Fatalf("expected tool to be a map not %s", tool)
		}
		// has a name
		if _, ok := mcpTool["name"]; !ok {
			t.Fatal("expected tool to have a name")
		}
		// has a description
		if _, ok := mcpTool["description"]; !ok {
			t.Fatal("expected tool to have a description")
		}
		// has an inputschema
		inputSchemaMaybe, ok := mcpTool["inputSchema"]
		if !ok {
			t.Fatal("expected tool to have an inputSchema")
		}
		// inputSchema is a map
		inputSchema, ok := inputSchemaMaybe.(map[string]interface{})
		if !ok {
			t.Fatal("expected inputSchema to be a map")
		}
		if _, ok := inputSchema["required"]; !ok {
			t.Fatal("expected inputSchema to have a required field")
		}
		if _, ok := inputSchema["type"]; !ok {
			t.Fatal("expected inputSchema to have a type field")
		}
		properties, ok := inputSchema["properties"]
		if !ok {
			t.Fatal("expected inputSchema to have a properties field")
		}
		propertiesMap, ok := properties.(map[string]interface{})
		if !ok {
			t.Fatal("expected properties to be a map")
		}
		for key, value := range propertiesMap {
			propertyMap, ok := value.(map[string]interface{})
			if !ok {
				t.Fatalf("expected property %s to be a map", key)
			}
			if _, ok := propertyMap["description"]; !ok {
				t.Fatalf("expected property %s to have a description", key)
			}
			if _, ok := propertyMap["type"]; !ok {
				t.Fatalf("expected property %s to have a type", key)
			}
		}

	}
}

func checkLoadProgramTool(t *testing.T, stdin io.WriteCloser, scanner *bufio.Scanner) {
	// Test load program tool
	loadProgramReq := jsonRPCRequest{
		JSONRPC: jsonRpcVersion,
		ID:      7,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "argot_load",
			"arguments": map[string]interface{}{
				"packages": []string{"./testdata/sample.go"},
			},
		},
	}
	sendRequest(t, stdin, loadProgramReq)
	response := readResponse(t, scanner)
	var loadProgramResp jsonRPCResponse
	if err := json.Unmarshal([]byte(response), &loadProgramResp); err != nil {
		t.Fatal(err)
	}
	if loadProgramResp.Error != nil {
		t.Fatalf("Load program failed: %v", loadProgramResp.Error)
	}
}

func checkListTool(t *testing.T, stdin io.WriteCloser, scanner *bufio.Scanner) {
	// Test load program tool
	loadProgramReq := jsonRPCRequest{
		JSONRPC: jsonRpcVersion,
		ID:      7,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "argot_list_functions",
			"arguments": map[string]interface{}{
				"regex": "command-line-arguments",
			},
		},
	}
	sendRequest(t, stdin, loadProgramReq)
	response := readResponse(t, scanner)
	var loadProgramResp jsonRPCResponse
	if err := json.Unmarshal([]byte(response), &loadProgramResp); err != nil {
		t.Fatal(err)
	}
	if loadProgramResp.Error != nil {
		t.Fatalf(" List functions failed: %v", loadProgramResp.Error)
	}
}
