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

package refactor_test

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/refactor"
	"github.com/dave/dst"
	"github.com/dave/dst/decorator"
	"github.com/dave/dst/decorator/resolver/gopackages"
	"golang.org/x/tools/go/packages"
)

func tmpPrintTest(r *decorator.Restorer, dir string, dstFile *dst.File) error {
	tmpFile := path.Join(dir, dstFile.Name.Name+"_tmp.go")
	file, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer func() {
		file.Close()
		os.Remove(tmpFile)
	}()
	// Output the file in temporary location
	err = r.Fprint(file, dstFile)
	if err != nil {
		return err
	}
	return nil
}

func TestInsertNilChecks(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/refactor/insertnil")

	config := &packages.Config{
		Mode:  analysis.PkgLoadMode,
		Tests: false,
	}

	// load, parse and type check the given packages
	loadedPackages, err := decorator.Load(config, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load packages: %s", err)
		os.Exit(1)
	}
	refactor.InsertNilChecks(loadedPackages)
	r := decorator.NewRestorerWithImports(dir, gopackages.New(dir))

	for _, pack := range loadedPackages {
		for _, dstFile := range pack.Syntax {
			r.Print(dstFile)
		}
	}
}
