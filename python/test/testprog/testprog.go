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
	"fmt"
	"io"
	"strings"
)

// GetUserInput simulates getting sensitive user input (SOURCE)
func GetUserInput() string {
	return "sensitive-user-data"
}

// LogPublicly logs data publicly (SINK - should not receive tainted data)
func LogPublicly(data string) {
	fmt.Println("PUBLIC LOG:", data)
}

// Sanitize removes sensitive information from data (SANITIZER)
func Sanitize(data string) string {
	return "***REDACTED***"
}

// SimpleFunction demonstrates a basic data flow from argument to return
func SimpleFunction(input string) string {
	return input
}

// ProcessData shows flow through struct fields
type DataProcessor struct {
	buffer []byte
}

func (dp *DataProcessor) Process(data []byte) []byte {
	dp.buffer = append(dp.buffer, data...)
	return dp.buffer
}

// ReadAndTransform demonstrates flow from interface to return
func ReadAndTransform(r io.Reader) ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// MultipleReturns shows flow to multiple return values
func MultipleReturns(x, y int) (int, int) {
	return x + y, x - y
}

// ClosureExample demonstrates closure with free variables
func ClosureExample(multiplier int) func(int) int {
	return func(x int) int {
		return x * multiplier
	}
}

// main demonstrates a taint flow problem and calls functions for summary generation
func main() {
	// Taint flow examples
	// This should trigger a taint warning: sensitive data flows to public log
	sensitiveData := GetUserInput()
	LogPublicly(sensitiveData)

	// This should NOT trigger a warning: data is sanitized
	sanitizedData := Sanitize(GetUserInput())
	LogPublicly(sanitizedData)

	// Call functions that need dataflow summaries
	_ = SimpleFunction("test")

	dp := &DataProcessor{}
	_ = dp.Process([]byte("data"))

	_, _ = MultipleReturns(1, 2)

	// ReadAndTransform with a strings.Reader
	reader := strings.NewReader("example data")
	_, _ = ReadAndTransform(reader)
}
