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

package summaries

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// rawSummaries represents a set of summaries
type rawSummaries struct {
	// DataflowSummaries
	DataflowSummaries []rawDataflowSummary `json:"dataflow-summaries" yaml:"dataflow-summaries"`
}

// rawDataflowSummary is a single dataflow summary, either for an interface method or for a function
type rawDataflowSummary struct {
	// Package is the package this dataflow summary corresponds to
	Package string `json:"package" yaml:"package"`
	// Interface is the interface summarized; method must be provided
	Interface string `json:"interface" yaml:"interface"`
	// Receiver is the receiver of the method being summarized
	Receiver string `json:"receiver" yaml:"receiver"`
	// Function is the function being summarized; interface and method are expected to be empty
	Function string `json:"function" yaml:"function"`
	// Method is the method name when interface is specified
	Method string `json:"method" yaml:"method"`
	// Flows is the list of data flows in the function or method being summarized
	Flows []FlowDesc `json:"flows" yaml:"flows"`
}

// FlowDesc is a data flow from an origin to a destination
type FlowDesc struct {
	// From is the origin of the dataflow. It can be an argument (incl. receiver).
	From string `json:"from" yaml:"from"`
	// To is the destination of the dataflow. It can be an argument (incl. receiver) or a return value.
	To string `json:"to" yaml:"to"`
}

// IfaceMethodFlowSummary is a dataflow summary for an interface method
type IfaceMethodFlowSummary struct {
	// pkg is the package this dataflow summary corresponds to
	pkg string
	// Interface is the interface being summarized
	Interface string
	// Method is the method being summarized
	Method string
	// summary is the dataflow summary
	summary detailedSummary
}

// Package reutrns the package this method summary corresponds to
func (s IfaceMethodFlowSummary) Package() string {
	return s.pkg
}

// Summary returns the of data flows in the function or method being summarized
func (s IfaceMethodFlowSummary) Summary() detailedSummary {
	return s.summary
}

// FunctionFlowSummary is a dataflow summary for a function
type FunctionFlowSummary struct {
	// pkg is the package this dataflow summary corresponds to
	pkg string
	// Function is the function being summarized
	Function string
	// summary is the dataflow summary
	summary detailedSummary
}

// Package returns the package this dataflow summary corresponds to
func (s FunctionFlowSummary) Package() string {
	return s.pkg
}

// Summary returns the data flows in the function or method being summarized
func (s FunctionFlowSummary) Summary() detailedSummary {
	return s.summary
}

// ReceiverMethodFlowSummary is a dataflow summary for a receiver method
type ReceiverMethodFlowSummary struct {
	// Package is the package this dataflow summary corresponds to
	pkg string
	// Receiver is the receiver of the method being summarized
	Receiver string
	// Method is the method being summarized
	Method string
	// summary is the dataflow summary
	summary detailedSummary
}

// Package returns the package this dataflow summary corresponds to
func (s ReceiverMethodFlowSummary) Package() string {
	return s.pkg
}

// Summary returns the data flows in the function or method being summarized
func (s ReceiverMethodFlowSummary) Summary() detailedSummary {
	return s.summary
}

// A FrontendDataflowSummary reprensetns either a function or a interface method summary
type FrontendDataflowSummary interface {
	Package() string
	Summary() detailedSummary
}

// ParseSummariesFile parses a file that represents a Summaries structure. The structure can be
// serialized either in yaml or json format.
func ParseSummariesFile(path string) ([]FrontendDataflowSummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var summaries *rawSummaries
	errJson := json.Unmarshal(content, &summaries)
	if errJson == nil {
		return summaries.compile()
	}
	// try yaml
	errYaml := yaml.Unmarshal(content, &summaries)
	if errYaml != nil {
		return nil, errors.Join(errJson, errYaml)
	}
	// validate
	return summaries.compile()
}

// compile rawSummaries into a list of FrontendDataflowSummary
//
// May return errors if validation fails.
func (summaries *rawSummaries) compile() ([]FrontendDataflowSummary, error) {
	var errs error
	var summariesFrontend []FrontendDataflowSummary
	for _, summary := range summaries.DataflowSummaries {
		fs, structureErr := summary.compile()
		if structureErr == nil {
			summariesFrontend = append(summariesFrontend, fs)
		}
		errs = errors.Join(errs, structureErr)
	}
	return summariesFrontend, errs
}

// compile validates and transforms a rawDataflowSummary into a FrontendDataflowSummary
//
//gocyclo:ignore
func (s rawDataflowSummary) compile() (FrontendDataflowSummary, error) {
	if s.Package == "" {
		return nil, fmt.Errorf("package is empty")
	}
	// It has to be either a receiver's method, an interface method or a function summary
	if s.Receiver == "" && s.Interface == "" && s.Function == "" {
		return nil, fmt.Errorf("interface and function are empty (package: %s)", s.Package)
	}
	// Can't be interface of receiver, it should be method of receiver
	if s.Interface != "" && s.Function != "" {
		return nil, fmt.Errorf("interface %s and function %s are both set", s.Interface, s.Function)
	}
	// Can't be function of receiver, it should be method of receiver
	if s.Receiver != "" && s.Function != "" {
		return nil, fmt.Errorf("receiver %s and function %s are both set", s.Receiver, s.Function)
	}
	// Can't have an interface and no method
	if s.Interface != "" && s.Method == "" {
		return nil, fmt.Errorf("interface %s is set, but method is empty", s.Interface)
	}
	// Can't have a receiver and no method
	if s.Receiver != "" && s.Method == "" {
		return nil, fmt.Errorf("receiver %s is set, but method is empty", s.Receiver)
	}
	// Can't have a function and a method
	if s.Function != "" && s.Method != "" {
		return nil, fmt.Errorf("function %s and method %s are both set", s.Function, s.Method)
	}
	flows, flowErr := compileSummaryFlows(s.Flows, s.Receiver != "" || s.Interface != "")
	if flowErr != nil {
		return nil, flowErr
	}
	if s.Interface != "" {
		// It's an interface method summary
		return IfaceMethodFlowSummary{
			pkg:       s.Package,
			Interface: s.Interface,
			Method:    s.Method,
			summary:   flows,
		}, nil
	} else if s.Method != "" {
		// It's a receiver method summary
		return ReceiverMethodFlowSummary{
			pkg:      s.Package,
			Receiver: s.Receiver,
			Method:   s.Method,
			summary:  flows,
		}, nil
	} else {
		// It's a function summary
		return FunctionFlowSummary{
			pkg:      s.Package,
			Function: s.Function,
			summary:  flows,
		}, nil
	}
}

func compileSummaryFlows(flows []FlowDesc, canUseReceiver bool) (detailedSummary, error) {
	rawSummary := rawSummary{Flows: map[string][]string{}}
	for _, flow := range flows {
		if flow.From == "" {
			return detailedSummary{}, fmt.Errorf("flow.From is empty")
		}
		if flow.To == "" {
			return detailedSummary{}, fmt.Errorf("flow.To is empty")
		}
		if _, ok := rawSummary.Flows[flow.From]; !ok {
			rawSummary.Flows[flow.From] = []string{}
		}
		if !canUseReceiver && (strings.Contains(flow.From, "!receiver") || strings.Contains(flow.To, "!receiver")) {
			return detailedSummary{}, fmt.Errorf("flow.From or flow.To contains !receiver, but not in a method's flow")
		}
		rawSummary.Flows[flow.From] = append(rawSummary.Flows[flow.From], flow.To)
	}
	return rawSummary.compile()
}
