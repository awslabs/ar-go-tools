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

func TestMCPServerDependenciesTool(t *testing.T) {
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
	response = readResponse(t, scanner)
	if !strings.Contains(response, "go_dependencies") {
		t.Error("go_dependencies tool not found")
	}

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
}

func sendRequest(t *testing.T, stdin io.WriteCloser, req jsonRPCRequest) {
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	stdin.Write(data)
	stdin.Write([]byte("\n"))
}

func readResponse(t *testing.T, scanner *bufio.Scanner) string {
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "{") {
			return line
		}
	}
	return ""
}
