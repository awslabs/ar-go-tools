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
	"fmt"
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
	IsSource      string `xml:"isSource,attr"`
	IsSink        string `xml:"isSink,attr"`
	IsSanitizer   string `xml:"isSanitizer,attr"`
	IsValidator   string `xml:"isValidator,attr"`
	DataflowSpecs string `xml:"dataflowSpecs,attr"`
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
			if obj.PkgFilter != "" {
				c.PkgFilter = obj.PkgFilter
			}
			if obj.Filters != "" {
				// TODO Filters
			}
			fmt.Printf("Options: %v\n", obj.Options)

			c.Options = obj.Options
		}

		cid := obj.CodeIdentifier

		if obj.IsSink == "true" {
			c.Sinks = append(c.Sinks, cid)
		}
		if obj.IsSource == "true" {
			c.Sources = append(c.Sources, cid)
		}
		if obj.IsSanitizer == "true" {
			c.Sanitizers = append(c.Sanitizers, cid)
		}
		if obj.IsValidator == "true" {
			c.Validators = append(c.Validators, cid)
		}
	}
	// TODO: use edges to infer which sources/sinks/sanitizers go together
	for _, edge := range x.Edge {
		fmt.Println(edge.Edge)
	}
	return nil

}
