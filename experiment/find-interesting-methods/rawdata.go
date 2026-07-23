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
	"encoding/json"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/taint"
)

// RawRecord is the fully-classified, JSON-serializable record for one interesting function.
// produce decides everything here (which to_summarize.json entries this function should
// contribute, and why it was classified as interesting) using the real *ssa.Function; consume
// only deduplicates Entries across records and writes the final to_summarize.json.
type RawRecord struct {
	// FuncString is the *ssa.Function's String() representation (e.g.
	// "(*crypto/ecdsa.PrivateKey).Sign"). Used for debugging/traceability, and to identify
	// timed-out functions in consume's output (see runConsume).
	FuncString string `json:"func"`
	// Entries are the to_summarize.json entries this function contributes: usually the function's
	// own concrete MethodEntry, but one entry per distinct public interface method if the
	// function was reached via interface dispatch (see classifyEntries). Empty if the function is
	// interesting but has no addressable entry (e.g. an unexported receiver with no usable
	// interface fanout).
	Entries []MethodEntry `json:"entries"`
	// Reasons lists exactly which criteria (see interestingReasons) classified this function as
	// interesting, so it's clear at a glance *why* a record was included instead of having to
	// cross-reference thresholds against the raw signal values below.
	Reasons []string `json:"reasons"`

	Unsoundness      []taint.UnsoundnessKind `json:"unsoundness,omitempty"`
	IntraTimeSeconds float64                 `json:"intra_time_seconds"`
	NumValues        int                     `json:"num_values"`
	IsRecursive      bool                    `json:"is_recursive,omitempty"`
	ContextLosses    []taint.ContextLoss     `json:"context_losses,omitempty"`
	InterfaceFanouts []taint.InterfaceFanout `json:"interface_fanouts,omitempty"`
}

// RawData is the full producer output: one RawRecord per interesting function.
type RawData struct {
	Records []RawRecord `json:"records"`
}

// NewRawRecord builds a RawRecord from f's identity, its decided entries, and its signals.
func NewRawRecord(funcString string, entries []MethodEntry, reasons []string,
	sig *taint.InterestingFunctionSignals) RawRecord {
	return RawRecord{
		FuncString:       funcString,
		Entries:          entries,
		Reasons:          reasons,
		Unsoundness:      sig.Unsoundness,
		IntraTimeSeconds: sig.IntraTime.Seconds(),
		NumValues:        sig.NumValues,
		IsRecursive:      sig.IsRecursive,
		ContextLosses:    sig.ContextLosses,
		InterfaceFanouts: sig.InterfaceFanouts,
	}
}

// WriteRawData writes data as JSON to path.
func WriteRawData(path string, data RawData) error {
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, bytes, 0o644)
}

// ReadRawData reads a RawData JSON file from path.
func ReadRawData(path string) (RawData, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return RawData{}, err
	}
	var data RawData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return RawData{}, err
	}
	return data, nil
}
