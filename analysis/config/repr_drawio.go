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

package config

import (
	"encoding/xml"
	"strings"
)

// MxFile is the toplevel file representation in a draio diagram
type MxFile struct {
	Object   []Object `xml:"diagram>mxGraphModel>root>object"`
	Cells    []mxCell `xml:"diagram>mxGraphModel>root>mxCell"`
	Modified string   `xml:"modified,attr"`
	Host     string   `xml:"host,attr"`
}

// Object represents an object in the drawio diagram
type Object struct {
	ID string `xml:"id,attr"`
	CodeIdentifier
	Options
	Forbidden     bool   `xml:"forbidden,attr"`
	Cell          mxCell `xml:"mxCell"`
	IsSource      bool   `xml:"taint-source,attr"`
	IsSink        bool   `xml:"taint-sink,attr"`
	IsSanitizer   bool   `xml:"taint-sanitizer,attr"`
	IsValidator   bool   `xml:"taint-validator,attr"`
	DataflowSpecs string `xml:"dataflow-specs,attr"`
	Filters       string `xml:"filters,attr"`
}

// mxCell represents a cell in the drawio diagram
type mxCell struct {
	ID        string `xml:"id,attr"`
	Vertex    bool   `xml:"vertex,attr"`
	Edge      bool   `xml:"edge,attr"`
	Source    string `xml:"source,attr"`
	Target    string `xml:"target,attr"`
	Forbidden bool   `xml:"forbidden,attr"`
}

// ParseXMLConfigFormat parses the bytes as xml, expecting a drawio file representing a diagram of dataflow problems
// where the options of the config are specified in the metadata.
func ParseXMLConfigFormat(c *Config, b []byte) error {
	x := &MxFile{}
	err := xml.Unmarshal(b, x)
	if err != nil {
		return err
	}

	sources := map[string]CodeIdentifier{}
	sinks := map[string]CodeIdentifier{}
	sanitizers := map[string]CodeIdentifier{}
	validators := map[string]CodeIdentifier{}

	for _, obj := range x.Object {
		// Object 0 should contain settings
		if obj.ID == "0" && !obj.Cell.Vertex && !obj.Cell.Edge {
			if obj.DataflowSpecs != "" {
				specs := strings.Split(obj.DataflowSpecs, ",")
				c.DataflowProblems.UserSpecs = specs
			}
			c.Options = obj.Options
		}

		// Vertex objects can be sinks, sources, etc..
		if obj.Cell.Vertex {
			cid := obj.CodeIdentifier

			if obj.IsSink {
				sinks[obj.ID] = cid
			} else if obj.IsSource {
				sources[obj.ID] = cid
			} else if obj.IsSanitizer {
				sanitizers[obj.ID] = cid
			} else if obj.IsValidator {
				validators[obj.ID] = cid
			}
		}
	}

	specs := map[string]*TaintSpec{}

	setProblems(c, x, sources, sinks, sanitizers, validators, specs)

	return nil
}

func setProblems(c *Config, x *MxFile,
	sources map[string]CodeIdentifier,
	sinks map[string]CodeIdentifier,
	sanitizers map[string]CodeIdentifier,
	validators map[string]CodeIdentifier,
	specs map[string]*TaintSpec) {
	for _, obj := range x.Object {
		if obj.Cell.Edge {
			handleEdge(obj.Cell, obj.Forbidden, sources, sinks, sanitizers, validators, specs)
		}
	}
	for _, cell := range x.Cells {
		if cell.Edge {
			handleEdge(cell, cell.Forbidden, sources, sinks, sanitizers, validators, specs)
		}
	}

	for _, spec := range specs {
		c.TaintTrackingProblems = append(c.TaintTrackingProblems, *spec)
	}
}

func handleEdge(cell mxCell, forbidden bool,
	sources map[string]CodeIdentifier,
	sinks map[string]CodeIdentifier,
	sanitizers map[string]CodeIdentifier,
	validators map[string]CodeIdentifier,
	specs map[string]*TaintSpec) {

	if forbidden {
		source, sourceExists := sources[cell.Source]
		sink, sinkExists := sinks[cell.Target]
		if sourceExists && sinkExists {
			ts, ok := specs[cell.Source]
			if !ok {
				ts = &TaintSpec{}
				specs[cell.Source] = ts
			}
			ts.Sources = append(ts.Sources, source)
			ts.Sinks = append(ts.Sinks, sink)
		}
		return
	}
	// is it a sanitizer?
	_, sourceExists := sources[cell.Source]
	sanitizer, sanitizerExists := sanitizers[cell.Target]
	if sourceExists && sanitizerExists {
		ts, ok := specs[cell.Source]
		if !ok {
			ts = &TaintSpec{}
			specs[cell.Source] = ts
		}
		ts.Sanitizers = append(ts.Sanitizers, sanitizer)
	}
	// Is it a validator?
	validator, validatorExists := validators[cell.Target]
	if sourceExists && validatorExists {
		ts, ok := specs[cell.Source]
		if !ok {
			ts = &TaintSpec{}
			specs[cell.Source] = ts
		}
		ts.Validators = append(ts.Validators, validator)
	}
}
