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
	"strconv"
	"strings"
)

type MxFile struct {
	Object   []Object `xml:"diagram>mxGraphModel>root>object"`
	Edge     []Edge   `xml:"diagram>mxGraphModel>root>mxCell"`
	Modified string   `xml:"modified,attr"`
	Host     string   `xml:"host,attr"`
}

type Object struct {
	Id                  string `xml:"id,attr"`
	Label               string `xml:"label,attr"`
	Package             string `xml:"package,attr"`
	Method              string `xml:"method,attr"`
	Type                string `xml:"type,attr"`
	Field               string `xml:"field,attr"`
	Receiver            string `xml:"receiver,attr"`
	Kind                string `xml:"kind,attr"`
	IsSource            string `xml:"isSource,attr"`
	IsSink              string `xml:"isSink,attr"`
	IsSanitizer         string `xml:"isSanitizer,attr"`
	IsValidator         string `xml:"isValidator,attr"`
	DataflowSpecs       string `xml:"dataflowSpecs,attr"`
	PkgFilter           string `xml:"pkgFilter,attr"`
	Filters             string `xml:"filters,attr"`
	UseEscapeAnalysis   string `xml:"useEscapeAnalysis,attr"`
	SkipInterprocedural string `xml:"skipInterprocedural,attr"`
	CoverageFilter      string `xml:"coverageFilter,attr"`
	ReportSummaries     string `xml:"reportsummaries,attr"`
	SummarizeOnDemand   string `xml:"summarizeOnDemand,attr"`
	IgnoreNonSummarized string `xml:"ignoreNonSummarized,attr"`
	SourceTaintsArgs    string `xml:"sourceTaintsArgs,attr"`
	ReportPaths         string `xml:"reportPaths,attr"`
	ReportCoverage      string `xml:"reportCoverage,attr"`
	ReportNoCalleeSites string `xml:"reportNoCalleeSites,attr"`
	MaxDepth            string `xml:"maxDepth,attr"`
	MaxAlarms           string `xml:"maxAlarms,attr"`
	LogLevel            string `xml:"logLevel,attr"`
	Warn                string `xml:"warn,attr"`
}

type Edge struct {
	Id     string `xml:"id,attr"`
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
			if obj.ReportSummaries == "true" {
				c.ReportSummaries = true
			}
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
			if obj.UseEscapeAnalysis == "true" {
				c.UseEscapeAnalysis = true
			}
			if obj.SkipInterprocedural == "true" {
				c.SkipInterprocedural = true
			}
			if obj.CoverageFilter != "" {
				c.CoverageFilter = obj.CoverageFilter
			}
			if obj.SummarizeOnDemand == "true" {
				c.SummarizeOnDemand = true
			}
			if obj.IgnoreNonSummarized == "true" {
				c.IgnoreNonSummarized = true
			}
			if obj.SourceTaintsArgs == "true" {
				c.SourceTaintsArgs = true
			}
			if obj.ReportPaths == "true" {
				c.ReportPaths = true
			}
			if obj.ReportCoverage == "true" {
				c.ReportCoverage = true
			}
			if obj.ReportNoCalleeSites == "true" {
				c.ReportNoCalleeSites = true
			}
			if obj.MaxDepth != "" {
				i, err := strconv.Atoi(obj.MaxDepth)
				if err != nil {
					return fmt.Errorf("maxDepth must be an integer")
				}
				c.MaxDepth = i
			}
			if obj.MaxAlarms != "" {
				i, err := strconv.Atoi(obj.MaxAlarms)
				if err != nil {
					return fmt.Errorf("maxAlarms must be an integer")
				}
				c.MaxAlarms = i
			}
			if obj.LogLevel != "" {
				i, err := strconv.Atoi(obj.LogLevel)
				if err != nil {
					return fmt.Errorf("logLevel must be an integer")
				}
				c.LogLevel = i
			}
			if obj.Warn == "false" {
				c.Warn = false
			}
		}
		cid := CodeIdentifier{
			Package:        obj.Package,
			Method:         obj.Method,
			Receiver:       obj.Receiver,
			Field:          obj.Field,
			Type:           obj.Type,
			Label:          obj.Label,
			Kind:           obj.Kind,
			computedRegexs: nil,
		}
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
	return nil

}
