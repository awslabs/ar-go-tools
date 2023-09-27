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

type MxFile struct {
	Object   []Object `xml:"diagram>mxGraphModel>root>object"`
	Edge     []Edge   `xml:"diagram>mxGraphModel>root>mxCell"`
	Modified string   `xml:"modified,attr"`
	Host     string   `xml:"host,attr"`
}

type Object struct {
	Id string `xml:"id,attr"`
	CodeIdentifier
	Options
	IsSource      string `xml:"taint-source,attr"`
	IsSink        string `xml:"taint-sink,attr"`
	IsSanitizer   string `xml:"taint-sanitizer,attr"`
	IsValidator   string `xml:"taint-validator,attr"`
	DataflowSpecs string `xml:"dataflow-specs,attr"`
	Filters       string `xml:"filters,attr"`
}

type Edge struct {
	Id     string `xml:"id,attr"`
	Edge   bool   `xml:"edge,attr"`
	Source string `xml:"source,attr"`
	Target string `xml:"target,attr"`
}

func ParseXmlConfigFormat(c *Config, b []byte) error {
	x := &MxFile{}
	err := xml.Unmarshal(b, x)
	if err != nil {
		return err
	}
	for _, obj := range x.Object {
		// Object 0 should contain settings
		if obj.Id == "0" {
			if obj.DataflowSpecs != "" {
				specs := strings.Split(obj.DataflowSpecs, ",")
				c.DataflowSpecs = specs
			}
			c.Options = obj.Options
		}

		cid := obj.CodeIdentifier

		ts := TaintSpec{}
		addSpec := false
		if obj.IsSink == "true" {
			ts.Sinks = append(ts.Sinks, cid)
			addSpec = true
		}
		if obj.IsSource == "true" {
			ts.Sources = append(ts.Sources, cid)
			addSpec = true
		}
		if obj.IsSanitizer == "true" {
			ts.Sanitizers = append(ts.Sanitizers, cid)
			addSpec = true
		}
		if obj.IsValidator == "true" {
			ts.Validators = append(ts.Validators, cid)
			addSpec = true
		}
		if addSpec {
			c.TaintTrackingProblems = append(c.TaintTrackingProblems, ts)
		}
	}
	// TODO: use edges to infer which sources/sinks/sanitizers go together
	return nil

}
