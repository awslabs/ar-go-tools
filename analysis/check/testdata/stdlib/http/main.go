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
	"net/http"
)

func main() {
	// Test net/http.Get - complex network stack with connection pooling
	resp, err := http.Get(source())
	if err != nil {
		fmt.Printf("HTTP error: %v\n", err)
	} else {
		fmt.Printf("HTTP status: %s\n", resp.Status)
		resp.Body.Close()
	}
}

func source() string {
	return "https://httpbin.org/get"
}
