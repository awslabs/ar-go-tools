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

/*
The Argot taint tool runs taint analysis on your code, using its SSA representation.

Usage:

	taint [flags] -config config.yaml main.go

The flags are:

	-buildmode=D      see the documentation of buildmode for the ssa package

	-config path      a path to the configuration file containing definitions for sinks and sources

	-verbose=false    setting verbose mode, overrides config file options if set
*/
package main
