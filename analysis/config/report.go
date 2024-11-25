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
	"encoding/json"
	"os"
	"sync"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// Errors contains errors generated during the different steps of the analysis, keyed by some string
// to reduce the number of duplicates.
type Errors struct {
	// Stored errors
	ErrorMap   map[string][]error
	errorMutex sync.Mutex
}

// ReportInfo contains the information in the main report of argot
type ReportInfo struct {
	CountBySeverity map[Severity]int

	// Reports groups entries by tag
	Reports map[string]ReportGroup

	// Errors contains the errors generated during the analysis
	Errors Errors
}

// A ReportGroup lists the report contents in each details file
type ReportGroup struct {
	Tool     ToolName
	Severity Severity
	Details  []string
}

// ReportEntry is one entry in the report, with high-level information about the severity and what tool
// generated it. Contents of the report should be stored in a separate content file.
type ReportEntry struct {
	Tool        ToolName
	ContentFile string
	Severity    Severity
}

// A ReportDesc gathers content and metadata about a specific report entry.
type ReportDesc struct {
	Tool     ToolName
	Tag      string
	Severity Severity
	Content  any
}

// NewReport returns a new ReportInfo with initialized maps
func NewReport() *ReportInfo {
	return &ReportInfo{
		CountBySeverity: map[Severity]int{},
		Reports:         map[string]ReportGroup{},
		Errors: Errors{
			ErrorMap:   map[string][]error{},
			errorMutex: sync.Mutex{},
		},
	}
}

// Merge merges the report elements of other into the receiver
func (r *ReportInfo) Merge(other *ReportInfo) {
	if other == nil {
		return
	}
	for sev, count := range other.CountBySeverity {
		r.IncrementSevCount(sev, count)
	}
	for tag, reportGroup := range other.Reports {
		if thisReportGroup, ok := r.Reports[tag]; ok {
			thisReportGroup.Details = append(thisReportGroup.Details, r.Reports[tag].Details...)
		} else {
			r.Reports[tag] = reportGroup
		}
	}
}

// IncrementSevCount increments the count of the provided severity label
func (r *ReportInfo) IncrementSevCount(sev Severity, count int) {
	if prev, ok := r.CountBySeverity[sev]; ok {
		r.CountBySeverity[sev] = prev + count
	} else {
		r.CountBySeverity[sev] = count
	}
}

func (r *ReportInfo) addEntry(tag string, entry ReportEntry) {
	if _, tagPresent := r.Reports[tag]; !tagPresent {
		r.Reports[tag] = ReportGroup{
			Tool:     entry.Tool,
			Severity: entry.Severity,
			Details:  []string{entry.ContentFile},
		}
		return
	}
	group := r.Reports[tag]
	newDetails := append(group.Details, entry.ContentFile)
	r.Reports[tag] = ReportGroup{
		Tool:     entry.Tool,
		Severity: entry.Severity,
		Details:  newDetails,
	}
}

// AddEntry write the information in the ReportDesc to a new file in the ReportsDir, and adds a new entry into the
// receiver.
func (r *ReportInfo) AddEntry(c Configurer, report ReportDesc) {
	r.IncrementSevCount(report.Severity, 1)
	logger := c.GetLogger()
	logger.Debugf("Write report for tool=%s, tag=%s, severity=%s", report.Tool, report.Tag, report.Severity)
	tmp, err := os.CreateTemp(c.GetConfig().ReportsDir, report.Tag+"-report-*.json")
	if err != nil {
		logger.Errorf("Could not write report for %s (severity %s)", report.Tag, report.Severity)
		return
	}
	defer tmp.Close()
	logger.Infof("Report in %s\n", formatutil.Sanitize(tmp.Name()))

	content, err := json.MarshalIndent(report.Content, "", "  ")
	if err != nil {
		logger.Errorf("Error serializing report: %s", err)
	}
	_, err = tmp.Write(content)
	logger.Infof("Write report for tool=%s, tag=%s, severity=%s in %s",
		report.Tool, report.Tag, report.Severity, tmp.Name())
	if err != nil {
		logger.Errorf("Error writing report: %s", err)
	}

	r.addEntry(report.Tag, ReportEntry{
		Tool:        report.Tool,
		ContentFile: tmp.Name(),
		Severity:    report.Severity,
	})
}

// Dump writes a new report file in the ReportsDir of the config file.
func (r *ReportInfo) Dump(c Configurer) {
	tmp, err := os.CreateTemp(c.GetConfig().ReportsDir, "overall-report-*.json")
	logger := c.GetLogger()
	if err != nil {
		logger.Errorf("Could not write final report: %s.", err)
		return
	}
	defer tmp.Close()
	payload, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		// This should not happen, there is no reason it should fail to marshal a simple struct of strings and lists
		// of strings
		panic("Failed to marshal report summary")
	}
	_, err = tmp.Write(payload)
	if err != nil {
		logger.Errorf("Failed to write report: %s. Please consult logs.", err)
	}
	logger.Infof("Wrote final report in %s", tmp.Name())
}

// AddError adds an error with key and error e to the state.
func (r *ReportInfo) AddError(key string, e error) {
	r.Errors.errorMutex.Lock()
	defer r.Errors.errorMutex.Unlock()
	if e != nil {
		r.Errors.ErrorMap[key] = append(r.Errors.ErrorMap[key], e)
	}
}

// CheckError checks whether there is an error in the state, and if there is, returns the first it encounters and
// deletes it. The slice returned contains all the errors associated with one single error key (as used in
// [*AnalyzerState.AddError])
func (r *ReportInfo) CheckError() []error {
	r.Errors.errorMutex.Lock()
	defer r.Errors.errorMutex.Unlock()
	for e, errs := range r.Errors.ErrorMap {
		delete(r.Errors.ErrorMap, e)
		return errs
	}
	return nil
}

// HasErrors returns true if the state has an error. Unlike [*AnalyzerState.CheckError], this is non-destructive.
func (r *ReportInfo) HasErrors() bool {
	r.Errors.errorMutex.Lock()
	defer r.Errors.errorMutex.Unlock()
	for _, errs := range r.Errors.ErrorMap {
		if len(errs) > 0 {
			return true
		}
	}
	return false
}
