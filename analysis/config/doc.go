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
Package config provides a simple way to manage configuration files.

Use [Load](filename) to load a configuration from a specific filename.

Use [SetGlobalConfig](filename) to set filename as the global config, and then [LoadGlobal]() to load the global config.

A config file should be in yaml or json format. The top-level fields can be any of the fields defined in the Config
struct type. The other fields  are defined by the types of the fields of [Config] and nested struct types.
For example, a valid config file is as follows:
options:

	log-level: 5

dataflow-problems:

	  taint-tracking:

		    -
			  sinks:
			    - package: fmt
		          method: Printf

			  sources:
			     - method: Read

# Identifying code elements

The config uses [CodeIdentifier] to identify specific code entities. For example, sinks and sources are CodeIdentifiers
which identifies specific functions in specific packages, or types, etc..
An important feature of the code identifiers is that the string specifications are seen as regexes if they can be
compiled to regexes, otherwise they are strings.

# Unsafe options

All the options that might affect the soundness of the results are prefixed by `unsafe-`, except for the configuration
options where the user provides function summaries (where it is assumed the user have soundly summarized the functions).
*/
package config
