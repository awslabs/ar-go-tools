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
	"fmt"
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
	// Context stores an additional string that can be used depending on context by analyses. Typically, one can use
	// Context to match the parent function name when matching a code identifier.
	Context string `xml:"context,attr"`

	// Package identifies the package of the code identifier.
	Package string `xml:"package,attr"` // in drawio input, package is an attribute

	// Interface identifies the interface name of the code identifier.
	Interface string `xml:"interface,attr"`

	// Package identifies the method/function of the code identifier. Method is used loosely here to mean function
	// or actual method
	Method string `xml:"method,attr"`

	// Receiver identified the receiver object of a method call
	Receiver string `xml:"receiver,attr"`

	// Field identifies a specific field
	Field string `xml:"field,attr"`

	// Type identifies a specific type, which can be used for example to identify allocation of a given type
	Type string `xml:"type,attr"`

	// Label can be used to store user-defined information about the code identifier.
	Label string `xml:"label,attr"`

	// Kind can be used to give additional semantic meaning to the code identifier. For example, it can be used
	// to tag a code identifier as a specific "channel receive"
	Kind string `xml:"kind,attr"`

	// computedRegexs is not part of the yaml config, but contains the compiled regex version of the code identifier
	// elements that are parsed as regexes.
	computedRegexs *codeIdentifierRegex
}

// NewCodeIdentifier properly intializes cid.
func NewCodeIdentifier(cid CodeIdentifier) CodeIdentifier {
	return compileRegexes(cid)
}

type codeIdentifierRegex struct {
	contextRegex   *regexp.Regexp
	packageRegex   *regexp.Regexp
	interfaceRegex *regexp.Regexp
	typeRegex      *regexp.Regexp
	methodRegex    *regexp.Regexp
	fieldRegex     *regexp.Regexp
	receiverRegex  *regexp.Regexp
}

// compileRegexes compiles the strings in the code identifier into regexes. It compiles all identifiers into regexes
// or none.
// @ensures cid.computedRegexs == null || cid.computedRegexs.(*) != null
// TODO improve error handling
func compileRegexes(cid CodeIdentifier) CodeIdentifier {
	contextRegex, err := regexp.Compile(cid.Context)
	if err != nil {
		fmt.Printf("[WARN] failed to compile context regex %v: %v\n", cid.Context, err)
	}
	packageRegex, err := regexp.Compile(cid.Package)
	if err != nil {
		fmt.Printf("[WARN] failed to compile package regex %v: %v\n", cid.Package, err)
	}
	interfaceRegex, err := regexp.Compile(cid.Interface)
	if err != nil {
		fmt.Printf("[WARN] failed to compile interface regex %v: %v\n", cid.Interface, err)
	}
	typeRegex, err := regexp.Compile(cid.Type)
	if err != nil {
		fmt.Printf("[WARN] failed to compile type regex %v: %v\n", cid.Type, err)
	}
	methodRegex, err := regexp.Compile(cid.Method)
	if err != nil {
		fmt.Printf("[WARN] failed to compile method regex %v: %v\n", cid.Method, err)
	}
	fieldRegex, err := regexp.Compile(cid.Field)
	if err != nil {
		fmt.Printf("[WARN] failed to compile field regex %v: %v\n", cid.Field, err)
	}
	receiverRegex, err := regexp.Compile(cid.Receiver)
	if err != nil {
		fmt.Printf("[WARN] failed to compile receiver regex %v: %v\n", cid.Receiver, err)
	}
	cid.computedRegexs = &codeIdentifierRegex{
		contextRegex,
		packageRegex,
		interfaceRegex,
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
		return ((cidRef.computedRegexs.contextRegex.MatchString(cid.Context)) || (cidRef.Context == "")) &&
			((cidRef.computedRegexs.packageRegex.MatchString(cid.Package)) || (cidRef.Package == "")) &&
			((cidRef.computedRegexs.packageRegex.MatchString(cid.Interface)) || (cidRef.Interface == "")) &&
			((cidRef.computedRegexs.methodRegex.MatchString(cid.Method)) || (cidRef.Method == "")) &&
			((cidRef.computedRegexs.receiverRegex.MatchString(cid.Receiver)) || (cidRef.Receiver == "")) &&
			((cidRef.computedRegexs.fieldRegex.MatchString(cid.Field)) || (cidRef.Field == "")) &&
			(cidRef.computedRegexs.typeRegex.MatchString(cid.Type) || (cidRef.Type == "")) &&
			(cidRef.Kind == cid.Kind)
	}
	return ((cid.Context == cidRef.Context) || (cidRef.Context == "")) &&
		((cid.Package == cidRef.Package) || (cidRef.Package == "")) &&
		((cid.Package == cidRef.Interface) || (cidRef.Interface == "")) &&
		((cid.Method == cidRef.Method) || (cidRef.Method == "")) &&
		((cid.Receiver == cidRef.Receiver) || (cidRef.Receiver == "")) &&
		((cid.Field == cidRef.Field) || (cidRef.Field == "")) &&
		((cid.Type == cidRef.Type) || (cidRef.Type == "")) &&
		(cidRef.Kind == cid.Kind)
}

// equalOnNonEmptyFields returns true if each of the receiver's fields (except
// the type) are either equal to the corresponding argument's field, or the
// argument's field is empty.
//
//gocyclo:ignore
func (cid *CodeIdentifier) equalOnNonEmptyFieldsExceptType(cidRef CodeIdentifier) bool {
	if cidRef.computedRegexs != nil {
		return ((cidRef.computedRegexs.contextRegex.MatchString(cid.Context)) || (cidRef.Context == "")) &&
			((cidRef.computedRegexs.packageRegex.MatchString(cid.Package)) || (cidRef.Package == "")) &&
			((cidRef.computedRegexs.packageRegex.MatchString(cid.Interface)) || (cidRef.Interface == "")) &&
			((cidRef.computedRegexs.methodRegex.MatchString(cid.Method)) || (cidRef.Method == "")) &&
			((cidRef.computedRegexs.receiverRegex.MatchString(cid.Receiver)) || (cidRef.Receiver == "")) &&
			((cidRef.computedRegexs.fieldRegex.MatchString(cid.Field)) || (cidRef.Field == "")) &&
			(cidRef.Kind == cid.Kind)
	}
	return ((cid.Context == cidRef.Context) || (cidRef.Context == "")) &&
		((cid.Package == cidRef.Package) || (cidRef.Package == "")) &&
		((cid.Package == cidRef.Interface) || (cidRef.Interface == "")) &&
		((cid.Method == cidRef.Method) || (cidRef.Method == "")) &&
		((cid.Receiver == cidRef.Receiver) || (cidRef.Receiver == "")) &&
		((cid.Field == cidRef.Field) || (cidRef.Field == "")) &&
		(cidRef.Kind == cid.Kind)
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

// FullMethodName returns the fully qualified name of the code identifier.
func (cid *CodeIdentifier) FullMethodName() string {
	if cid.Method != "" {
		return fmt.Sprintf("%v.%v.%v", cid.Package, cid.Receiver, cid.Method)
	}
	if cid.Interface != "" {
		return fmt.Sprintf("%v.%v", cid.Package, cid.Interface)
	}

	return "<invalid-cid>"
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
	if cid == nil {
		return false
	}
	if f == nil {
		return cid.Method == "" && cid.Package == ""
	}
	pkg := lang.PackageNameFromFunction(f)
	if cid.computedRegexs != nil && cid.computedRegexs.methodRegex != nil && cid.computedRegexs.packageRegex != nil {

		return cid.computedRegexs.packageRegex.MatchString(pkg) && cid.computedRegexs.methodRegex.MatchString(f.Name())
	}
	return cid.Method == f.Name() && cid.Package == pkg
}

// MatchInterface matches a function to a code identifier by looking whether that function implements an interface's
// method, and using that method information to match against the code identifier
func (cid *CodeIdentifier) MatchInterface(f *ssa.Function) bool {
	if cid == nil {
		return false
	}
	if f == nil {
		return cid.Package == "" && cid.Interface == ""
	}

	pkg := lang.PackageNameFromFunction(f)
	if cid.computedRegexs != nil && cid.computedRegexs.packageRegex != nil && cid.computedRegexs.interfaceRegex != nil {
		return cid.computedRegexs.packageRegex.MatchString(pkg) && cid.computedRegexs.interfaceRegex.MatchString(f.Type().String())
	}

	return cid.Package == pkg && cid.Interface == f.Type().String()
}
