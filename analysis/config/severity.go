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

// Severity is the severity label of an analysis problem
type Severity string

const (
	// Critical severity: often triggers early failure in analyses
	Critical Severity = "CRITICAL"
	// High severity
	High Severity = "HIGH"
	// Medium severity problems
	Medium Severity = "MEDIUM"
	// Low severity problems
	Low Severity = "LOW"
)

// IsValidSeverityStr returns true is the string s is a valid severity strings
func IsValidSeverityStr(s string) bool {
	switch s {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return true
	default:
		return false
	}
}

func (s Severity) String() string {
	return string(s)
}
