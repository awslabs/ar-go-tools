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
	"log"

	"github.com/adrg/xdg"
)

func main() {
	// Display XDG Base Directory paths
	fmt.Printf("Data Home: %s\n", xdg.DataHome)
	fmt.Printf("Config Home: %s\n", xdg.ConfigHome)
	fmt.Printf("Cache Home: %s\n", xdg.CacheHome)
	
	// Create a config file path
	configPath, err := xdg.ConfigFile("myapp/config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Config file path: %s\n", configPath)
	
	// Display user directories
	fmt.Printf("Desktop: %s\n", xdg.UserDirs.Desktop)
	fmt.Printf("Downloads: %s\n", xdg.UserDirs.Download)
}
