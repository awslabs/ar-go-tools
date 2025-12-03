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

//go:generate cp -r ../../doc ./doc

package main

import (
	_ "embed"
	"fmt"
	"strings"
)

type docResource struct {
	URI         string
	Name        string
	Description string
	MimeType    string
	Filename    string
}

var documentationResources = []docResource{
	{URI: "argot://doc/00_intro.md", Name: "Introduction", Description: "Introduction to Argot static analysis tools", MimeType: "text/markdown", Filename: "00_intro.md"},
	{URI: "argot://doc/01_taint.md", Name: "Taint Analysis", Description: "Guide to taint analysis in Argot", MimeType: "text/markdown", Filename: "01_taint.md"},
	{URI: "argot://doc/02_backtrace.md", Name: "Backtrace Analysis", Description: "Guide to backtrace analysis in Argot", MimeType: "text/markdown", Filename: "02_backtrace.md"},
	{URI: "argot://doc/03_argotcli.md", Name: "Argot CLI", Description: "Interactive CLI interface documentation", MimeType: "text/markdown", Filename: "03_argotcli.md"},
	{URI: "argot://doc/04_compare.md", Name: "Compare Tool", Description: "Function reachability comparison tool", MimeType: "text/markdown", Filename: "04_compare.md"},
	{URI: "argot://doc/05_defer.md", Name: "Defer Analysis", Description: "Defer statement analysis", MimeType: "text/markdown", Filename: "05_defer.md"},
	{URI: "argot://doc/06_dependencies.md", Name: "Dependencies Analysis", Description: "Dependency analysis tool documentation", MimeType: "text/markdown", Filename: "06_dependencies.md"},
	{URI: "argot://doc/07_maypanic.md", Name: "May-Panic Analysis", Description: "May-panic analysis documentation", MimeType: "text/markdown", Filename: "07_maypanic.md"},
	{URI: "argot://doc/08_packagescan.md", Name: "Package Scan", Description: "Package scanning tool documentation", MimeType: "text/markdown", Filename: "08_packagescan.md"},
	{URI: "argot://doc/09_reachability.md", Name: "Reachability Analysis", Description: "Reachability analysis documentation", MimeType: "text/markdown", Filename: "09_reachability.md"},
	{URI: "argot://doc/10_render.md", Name: "Render Tool", Description: "Graph and SSA rendering tool", MimeType: "text/markdown", Filename: "10_render.md"},
	{URI: "argot://doc/11_racerg.md", Name: "Race Detector", Description: "Static data race detector documentation", MimeType: "text/markdown", Filename: "11_racerg.md"},
	{URI: "argot://doc/12_syntactic.md", Name: "Syntactic Analysis", Description: "Syntactic analysis tool documentation", MimeType: "text/markdown", Filename: "12_syntactic.md"},
	{URI: "argot://doc/13_mcp_server.md", Name: "MCP Server", Description: "MCP server setup and usage guide", MimeType: "text/markdown", Filename: "13_mcp_server.md"},
}

func (s *serverState) handleResourcesList(req jsonRPCRequest) {
	resources := make([]map[string]interface{}, len(documentationResources))
	for i, doc := range documentationResources {
		resources[i] = map[string]interface{}{
			"uri":         doc.URI,
			"name":        doc.Name,
			"description": doc.Description,
			"mimeType":    doc.MimeType,
		}
	}
	s.sendResponse(req.ID, map[string]interface{}{"resources": resources})
}

func (s *serverState) handleResourcesRead(req jsonRPCRequest) {
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		s.sendError(req.ID, codeInvalidParams, "Invalid params")
		return
	}

	uri, ok := params["uri"].(string)
	if !ok {
		s.sendError(req.ID, codeInvalidParams, "uri parameter is required")
		return
	}

	if !strings.HasPrefix(uri, "argot://doc/") {
		s.sendError(req.ID, codeInvalidParams, fmt.Sprintf("Unknown resource URI: %s", uri))
		return
	}

	// Find the resource
	var resource *docResource
	for i := range documentationResources {
		if documentationResources[i].URI == uri {
			resource = &documentationResources[i]
			break
		}
	}

	if resource == nil {
		s.sendError(req.ID, codeInvalidParams, fmt.Sprintf("Unknown resource URI: %s", uri))
		return
	}

	// Read embedded content
	content, err := docContent(resource.Filename)
	if err != nil {
		s.sendError(req.ID, codeInternalError, fmt.Sprintf("Failed to read resource: %v", err))
		return
	}

	s.sendResponse(req.ID, map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"uri":      uri,
				"mimeType": "text/markdown",
				"text":     content,
			},
		},
	})
}

//go:embed doc/00_intro.md
var doc00 string

//go:embed doc/01_taint.md
var doc01 string

//go:embed doc/02_backtrace.md
var doc02 string

//go:embed doc/03_argotcli.md
var doc03 string

//go:embed doc/04_compare.md
var doc04 string

//go:embed doc/05_defer.md
var doc05 string

//go:embed doc/06_dependencies.md
var doc06 string

//go:embed doc/07_maypanic.md
var doc07 string

//go:embed doc/08_packagescan.md
var doc08 string

//go:embed doc/09_reachability.md
var doc09 string

//go:embed doc/10_render.md
var doc10 string

//go:embed doc/11_racerg.md
var doc11 string

//go:embed doc/12_syntactic.md
var doc12 string

//go:embed doc/13_mcp_server.md
var doc13 string

func docContent(filename string) (string, error) {
	switch filename {
	case "00_intro.md":
		return doc00, nil
	case "01_taint.md":
		return doc01, nil
	case "02_backtrace.md":
		return doc02, nil
	case "03_argotcli.md":
		return doc03, nil
	case "04_compare.md":
		return doc04, nil
	case "05_defer.md":
		return doc05, nil
	case "06_dependencies.md":
		return doc06, nil
	case "07_maypanic.md":
		return doc07, nil
	case "08_packagescan.md":
		return doc08, nil
	case "09_reachability.md":
		return doc09, nil
	case "10_render.md":
		return doc10, nil
	case "11_racerg.md":
		return doc11, nil
	case "12_syntactic.md":
		return doc12, nil
	case "13_mcp_server.md":
		return doc13, nil
	default:
		return "", fmt.Errorf("unknown file: %s", filename)
	}
}
