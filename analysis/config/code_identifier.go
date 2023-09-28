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

import (
	"go/types"
	"regexp"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

// A CodeIdentifier identifies a code element that is a source, sink, sanitizer, etc..
// A code identifier can be identified from its package, method, receiver, field
// or type, or any combination of those
// This is meant to replicate functionality in go-flow-levee and gokart, and can be
// extended as needed
type CodeIdentifier struct {
	Package  string `xml:"package,attr"` // in drawio input, package is an attribute
	Method   string `xml:"method,attr"`
	Receiver string `xml:"receiver,attr"`
	Field    string `xml:"field,attr"`
	Type     string `xml:"type,attr"`
	Label    string `xml:"label,attr"`
	Kind     string `xml:"kind,attr"`
	// This will not be part of the yaml config
	computedRegexs *codeIdentifierRegex
}
type codeIdentifierRegex struct {
	packageRegex  *regexp.Regexp
	typeRegex     *regexp.Regexp
	methodRegex   *regexp.Regexp
	fieldRegex    *regexp.Regexp
	receiverRegex *regexp.Regexp
}

// compileRegexes compiles the strings in the code identifier into regexes. It compiles all identifiers into regexes
// or none.
// @ensures cid.computedRegexs != null || cid.computedRegexs.(*) != null
func compileRegexes(cid CodeIdentifier) CodeIdentifier {
	packageRegex, err := regexp.Compile(cid.Package)
	if err != nil {
		return cid
	}
	typeRegex, err := regexp.Compile(cid.Type)
	if err != nil {
		return cid
	}
	methodRegex, err := regexp.Compile(cid.Method)
	if err != nil {
		return cid
	}
	fieldRegex, err := regexp.Compile(cid.Field)
	if err != nil {
		return cid
	}
	receiverRegex, err := regexp.Compile(cid.Receiver)
	if err != nil {
		return cid
	}
	cid.computedRegexs = &codeIdentifierRegex{
		packageRegex,
		typeRegex,
		methodRegex,
		fieldRegex,
		receiverRegex,
	}
	return cid
}

// equalOnNonEmptyFields returns true if each of the receiver's fields are either equal to the corresponding
// argument's field, or the argument's field is empty
//
//gocyclo:ignore
func (cid *CodeIdentifier) equalOnNonEmptyFields(cidRef CodeIdentifier) bool {
	if cidRef.computedRegexs != nil {
		return ((cidRef.computedRegexs.packageRegex.MatchString(cid.Package)) || (cidRef.Package == "")) &&
			((cidRef.computedRegexs.methodRegex.MatchString(cid.Method)) || (cidRef.Method == "")) &&
			((cidRef.computedRegexs.receiverRegex.MatchString(cid.Receiver)) || (cidRef.Receiver == "")) &&
			((cidRef.computedRegexs.fieldRegex.MatchString(cid.Field)) || (cidRef.Field == "")) &&
			(cidRef.computedRegexs.typeRegex.MatchString(cid.Type) || (cidRef.Type == "")) &&
			(cidRef.Kind == cid.Kind)
	} else {
		return ((cid.Package == cidRef.Package) || (cidRef.Package == "")) &&
			((cid.Method == cidRef.Method) || (cidRef.Method == "")) &&
			((cid.Receiver == cidRef.Receiver) || (cidRef.Receiver == "")) &&
			((cid.Field == cidRef.Field) || (cidRef.Field == "")) &&
			((cid.Type == cidRef.Type) || (cidRef.Type == "")) &&
			(cidRef.Kind == cid.Kind)
	}
}

// ExistsCid is true if there is some x in a such that f(x) is true.
// O(len(a))
func ExistsCid(a []CodeIdentifier, f func(identifier CodeIdentifier) bool) bool {
	for _, x := range a {
		if f(x) {
			return true
		}
	}
	return false
}

// MatchType checks whether the code identifier matches the type represented as a types.Type. It is safe to call with
// nil values.
func (cid *CodeIdentifier) MatchType(typ types.Type) bool {
	if cid == nil {
		return false
	}
	if typ == nil {
		return cid.Type == ""
	}
	if cid.computedRegexs != nil && cid.computedRegexs.typeRegex != nil {
		return cid.computedRegexs.typeRegex.MatchString(typ.String())
	}
	return cid.Type == typ.String()
}

// MatchPackageAndMethod checks whether the function f matches the code identifier on the package and method fields.
// It is safe to call with nil values.
func (cid *CodeIdentifier) MatchPackageAndMethod(f *ssa.Function) bool {
	pkg := lang.PackageNameFromFunction(f)
	if cid == nil {
		return false
	}
	if f == nil {
		return cid.Method == "" && cid.Package == ""
	}
	if cid.computedRegexs != nil && cid.computedRegexs.methodRegex != nil && cid.computedRegexs.packageRegex != nil {

		return cid.computedRegexs.packageRegex.MatchString(pkg) && cid.computedRegexs.methodRegex.MatchString(f.Name())
	}
	return cid.Method == f.Name() && cid.Package == pkg
}
