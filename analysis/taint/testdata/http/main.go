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
	"io"
	"net/http"
)

type handler struct{}

var _ http.Handler = (*handler)(nil)

func newHandler() handler {
	return handler{}
}

func (h handler) ServeHTTP(w http.ResponseWriter, hr *http.Request) {
	data := source() // @Source(handler)
	sink(w, data)    // @Sink(handler)
}

func source() string {
	return "tainted"
}

func sink(w io.Writer, data string) {
	w.Write([]byte(data))
}

func main() {
	h := newHandler()
	http.Handle("/", h)
	http.ListenAndServe("addr", h)
}
