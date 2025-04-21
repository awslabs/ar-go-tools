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

package formatutil

import (
	"strings"
)

// Unquote removes the quotes from a string, if it has quotes in first and last positions
func Unquote(s string) string {
	if len(s) > 1 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// LowerFirst just returns the string with the first character in lowercase.
func LowerFirst(s string) string {
	return strings.ToLower(s[0:1]) + s[1:]
}

// UpperFirst just returns the string with the first character in uppercase.
func UpperFirst(s string) string {
	return strings.ToUpper(s[0:1]) + s[1:]
}

// FormatLastSplit splits strings s with sep and applies the formatter to the last part of the
// split string, and then concatenates the strings again before returning it.
func FormatLastSplit(s string, sep string, formatter func(...any) string) string {
	sls := strings.Split(s, sep)
	sls[len(sls)-1] = formatter(sls[len(sls)-1])
	return strings.Join(sls, sep)
}
