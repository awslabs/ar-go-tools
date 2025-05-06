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

package specs

import (
	"fmt"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/scanning"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// A ParsedCodeIdentifier identifies a code element that is a source, sink, sanitizer, etc..
// A code identifier can be identified from its package, method, receiver, field
// or type, or any combination of those
// This is meant to replicate functionality in go-flow-levee and gokart, and can be
// extended as needed
type ParsedCodeIdentifier struct {
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

	// Const identifies a named package-level constant.
	// The Package field must be set as well.
	Const string `xml:"const,attr"`

	// Label can be used to store user-defined information about the code identifier.
	Label string `xml:"label,attr"`

	// Kind can be used to give additional semantic meaning to the code identifier. For example, it can be used
	// to tag a code identifier as a specific "channel receive"
	Kind string `xml:"kind,attr"`

	// ValueMatch can be used to match specific calls to a function. This is useful to match specific calls to
	// formatting functions.
	ValueMatch string `xml:"value-match,attr" yaml:"value-match" json:"value-match"`

	// computedRegexs is not part of the yaml config, but contains the compiled regex version of the code identifier
	// elements that are parsed as regexes.
	computedRegexs *codeIdentifierRegex

	// --- Fields for the new format: ---

	// Target identifies a program value that the analysis should analyze as an
	// entrypoint.
	// It can be "narrowed" further if needed to match specific objects that are
	// part of the target.
	Target Target

	// Enclosing specifies the calling context of the target (only for method targets).
	Enclosing CallingContext
}

// Compile generates a code specification by compiling a parsed code identifier
func (cid ParsedCodeIdentifier) Compile() ([]scanning.CodeSpec, error) {
	return cid.CompileForceArg(false)
}

// CompileForceArg generates a code specification by compiling a parsed code identifier
// the forceArg argument indicates whether a call spec should be forced into a
// call argument spec. This makes sense for sinks, and because of backwards compatibility
func (cid ParsedCodeIdentifier) CompileForceArg(forceArg bool) ([]scanning.CodeSpec, error) {
	if isNewFormat(cid) {
		return cid.compileNewFormat()
	}
	// First compile the context part
	common := scanning.CommonSpec{
		Package:        asRegex(cid.Package),
		ContextPackage: nil,
		ContextMethod:  asRegex(cid.Context),
	}

	// Try to distinguish the cases
	if cid.Kind == "channel receive" {
		return []scanning.CodeSpec{&scanning.ChannelRecvSpec{
			CommonSpec: common,
			Type:       asRegex(cid.Type),
			ValueMatch: asRegex(cid.ValueMatch),
		}}, nil
	}

	if cid.Method != "" &&
		cid.Package == "" &&
		scanning.MatchesHandledBuiltinCall(asRegex(cid.Method)) {
		return []scanning.CodeSpec{&scanning.BuiltinCallSpec{
			Name: trimStartEndRegex(cid.Method),
		}}, nil
	}

	// Method or interface indicate this is a call site
	if cid.Method != "" || cid.Interface != "" || cid.Receiver != "" {
		// It's a CallSpec
		callspec := scanning.CallSpec{
			CommonSpec:   common,
			Interface:    asRegex(cid.Interface),
			Method:       asRegex(cid.Method),
			ReceiverType: asRegex(cid.Receiver),
			ValueMatch:   asRegex(cid.ValueMatch),
		}

		if cid.Kind == "arg" || forceArg {
			return []scanning.CodeSpec{scanning.CallArgSpec{
				CallSpec: callspec,
				Type:     asRegex(cid.Type),
				Name:     regexp.MustCompile(".*"),
				AnyIndex: true,
			}}, nil
		}
		return []scanning.CodeSpec{callspec}, nil
	}

	if cid.Field != "" {
		return []scanning.CodeSpec{&scanning.StructFieldSpec{
			CommonSpec: common,
			Type:       asRegex(cid.Type),
			Field:      asRegex(cid.Field),
			Write:      forceArg,
		}}, nil
	}

	if cid.Type != "" {
		return []scanning.CodeSpec{&scanning.TypeSpec{
			CommonSpec: common,
			Type:       asRegex(cid.Type),
		}}, nil
	}
	panic(fmt.Sprintf("TODO: implement translation for %+v", cid))
}

func (cid ParsedCodeIdentifier) compileNewFormat() ([]scanning.CodeSpec, error) {
	var contextPkgRegex *regexp.Regexp
	var err error
	emptyMatch := regexp.MustCompile("")
	if cid.Enclosing.PackageRegex != "" {
		contextPkgRegex, err = regexp.Compile(cid.Enclosing.PackageRegex)
		if err != nil {
			return nil, err
		}
	} else if cid.Enclosing.Package != "" {
		// only exact match when non-empty is specified; it doesn't make sense otherwise
		contextPkgRegex = asExactMatchRegex(cid.Enclosing.Package)
	} else {
		contextPkgRegex = emptyMatch
	}

	var contextMethodRegex *regexp.Regexp
	var packageRegex *regexp.Regexp
	if cid.Enclosing.MethodRegex != "" {
		contextMethodRegex, err = regexp.Compile(cid.Enclosing.MethodRegex)
		if err != nil {
			return nil, err
		}
	} else if cid.Enclosing.Method != "" {
		// only exact match when non-empty is specified; it doesn't make sense otherwise
		contextMethodRegex = asExactMatchRegex(cid.Enclosing.Method)
	} else {
		contextMethodRegex = emptyMatch
	}
	if cid.Target.PackageRegex != "" {
		packageRegex = asRegex(cid.Target.PackageRegex)
		if cid.Target.Package != "" {
			return nil, fmt.Errorf(
				"should not specify both package regex %q and package %q in target",
				cid.Target.PackageRegex,
				cid.Target.Package,
			)
		}
	} else {
		packageRegex = asExactMatchRegex(cid.Target.Package)
	}
	common := &scanning.CommonSpec{
		Package:        packageRegex,
		ContextPackage: contextPkgRegex,
		ContextMethod:  contextMethodRegex,
	}
	switch cid.Target.Kind {
	case CallKind:
		if len(cid.Target.Objects) == 0 {
			return []scanning.CodeSpec{scanning.CallSpec{
				CommonSpec: *common,
				Method:     asExactMatchRegex(cid.Target.Method),
			}}, nil
		}
		specs := []scanning.CodeSpec{}
		for _, object := range cid.Target.Objects {
			if object.Kind == ArgumentKind {
				specs = append(specs, scanning.CallArgSpec{
					CallSpec: scanning.CallSpec{
						CommonSpec: *common,
						Method:     asRegex(cid.Target.Method),
					},
					Index: object.Index,
					Type:  asExactMatchRegex(object.Type),
					Name:  asExactMatchRegex(object.Name),
				})
			}
		}
		return specs, nil
	}
	return nil, fmt.Errorf("unrecognized code identifier")
}

// Target matches a specific program value to be analyzed as an
// entrypoint.
type Target struct {
	// Kind is the kind of target.
	// Supported kinds:
	// - "call"
	Kind TargetKind

	// Package is the name of the package that the method belongs to.
	Package string

	// PackageRegex is the regex of the package that the method belongs to.
	PackageRegex string `xml:"package-regex,attr" yaml:"package~" json:"package~"`

	// Method is the name of the method or function.
	Method string

	// Objects are the specific objects (values) in the target that the analysis
	// should analyze as an entrypoints.
	//
	// A "target object" can be an argument, return value, etc.
	// The supported kinds of objects depend on the kind of the target.
	Objects []TargetObject
}

// CallingContext matches a function/method that specifies the calling context
// of the target.
type CallingContext struct {
	Package        string
	PackageRegex   string `xml:"package-regex,attr" yaml:"package~" json:"package~"`
	Method         string
	MethodRegex    string `xml:"method-regex,attr" yaml:"method~" json:"method~"`
	computedRegexs *callingContextRegex
}

type callingContextRegex struct {
	packageRegex *regexp.Regexp
	methodRegex  *regexp.Regexp
}

// TargetKind is the kind of target.
type TargetKind string

const (
	// CallKind indicates a function/method call target.
	CallKind TargetKind = "call"
)

// TargetObject is a specific object value in the target that the analysis
// should analyze as an entrypoint.
type TargetObject struct {
	// Kind is the kind of entrypoint.
	//
	// Supported Kinds:
	// - "argument"
	Kind ObjectKind

	// Name is the (optional) name of the entrypoint.
	//
	// For example, if the Kind is an argument, `Name` should be set to the
	// parameter name in the function.
	Name string

	// Index is the index of the entrypoint.
	//
	// If the Kind is an argument, Index is the argument index.
	// If the Kind is a return value, Index specifies which returned tuple
	// element is the entrypoint.
	Index uint

	// Type is the type of the entrypoint.
	Type string
}

// ObjectKind is the kind of entrypoint object.
type ObjectKind string

const (
	// ArgumentKind indicates an function call argument entrypoint.
	ArgumentKind ObjectKind = "argument"
	// ReturnKind indicates a return value entrypoint.
	// TODO implement support
	// ReturnKind ObjectKind = "return"
)

// isNewFormat returns true if cid is specified using the new format.
func isNewFormat(cid ParsedCodeIdentifier) bool {
	return cid.Target.Kind != ""
}

type codeIdentifierRegex struct {
	contextRegex    *regexp.Regexp
	packageRegex    *regexp.Regexp
	interfaceRegex  *regexp.Regexp
	typeRegex       *regexp.Regexp
	methodRegex     *regexp.Regexp
	fieldRegex      *regexp.Regexp
	receiverRegex   *regexp.Regexp
	valueMatchRegex *regexp.Regexp
	constRegex      *regexp.Regexp
}

// CompileRegexes compiles the strings in the code identifier into regexes. It compiles all identifiers into regexes
// or none.
// @ensures cid.computedRegexs == null || cid.computedRegexs.(*) != null
// TODO improve error handling
func CompileRegexes(cid ParsedCodeIdentifier) ParsedCodeIdentifier {
	if isNewFormat(cid) {
		// Enclosing is the only object that may contain regexes (for now)
		cid.Enclosing.computedRegexs = &callingContextRegex{}
		if cid.Enclosing.PackageRegex != "" {
			packageRegex, err := regexp.Compile(cid.Enclosing.PackageRegex)
			if err != nil {
				fmt.Printf("[WARN] failed to compile enclosing package regex %v: %v\n", cid.Enclosing.PackageRegex, err)
			}
			cid.Enclosing.computedRegexs.packageRegex = packageRegex
		}
		if cid.Enclosing.MethodRegex != "" {
			methodRegex, err := regexp.Compile(cid.Enclosing.MethodRegex)
			if err != nil {
				fmt.Printf("[WARN] failed to compile enclosing method regex %v: %v\n", cid.Enclosing.MethodRegex, err)
			}
			cid.Enclosing.computedRegexs.methodRegex = methodRegex
		}

		return cid
	}

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
	valueMatchRegex, err := regexp.Compile(cid.ValueMatch)
	if err != nil {
		fmt.Printf("[WARN] failed to compile value match regex %v: %v\n", cid.ValueMatch, err)
	}
	constRegex, err := regexp.Compile(cid.Const)
	if err != nil {
		fmt.Printf("[WARN] failed to compile const regex %v: %v\n", cid.Const, err)
	}
	cid.computedRegexs = &codeIdentifierRegex{
		contextRegex,
		packageRegex,
		interfaceRegex,
		typeRegex,
		methodRegex,
		fieldRegex,
		receiverRegex,
		valueMatchRegex,
		constRegex,
	}
	return cid
}

// EqualOnNonEmptyFields returns true if each of the receiver's fields are either equal to the corresponding
// argument's field, or the argument's field is empty
//
//gocyclo:ignore
func (cid *ParsedCodeIdentifier) EqualOnNonEmptyFields(cidRef ParsedCodeIdentifier) bool {
	if isNewFormat(cidRef) {
		// Returns false if cid is not in the new format as well
		return cid.equalNewFormat(cidRef)
	}

	if cidRef.computedRegexs != nil {
		return ((cidRef.computedRegexs.contextRegex.MatchString(cid.Context)) || (cidRef.Context == "")) &&
			((cidRef.computedRegexs.packageRegex.MatchString(cid.Package)) || (cidRef.Package == "")) &&
			((cidRef.computedRegexs.packageRegex.MatchString(cid.Interface)) || (cidRef.Interface == "")) &&
			((cidRef.computedRegexs.methodRegex.MatchString(cid.Method)) || (cidRef.Method == "")) &&
			((cidRef.computedRegexs.receiverRegex.MatchString(cid.Receiver)) || (cidRef.Receiver == "")) &&
			((cidRef.computedRegexs.constRegex.MatchString(cid.Const)) || (cidRef.Const == "")) &&
			((cidRef.computedRegexs.fieldRegex.MatchString(cid.Field)) || (cidRef.Field == "")) &&
			(cidRef.computedRegexs.typeRegex.MatchString(cid.Type) || cidRef.Type == "") &&
			(cidRef.computedRegexs.valueMatchRegex.MatchString(cid.ValueMatch) || cidRef.ValueMatch == "") &&
			(cidRef.Kind == cid.Kind)
	}
	return ((cid.Context == cidRef.Context) || (cidRef.Context == "")) &&
		((cid.Package == cidRef.Package) || (cidRef.Package == "")) &&
		((cid.Package == cidRef.Interface) || (cidRef.Interface == "")) &&
		((cid.Method == cidRef.Method) || (cidRef.Method == "")) &&
		((cid.Receiver == cidRef.Receiver) || (cidRef.Receiver == "")) &&
		((cid.Const == cidRef.Const) || (cidRef.Const == "")) &&
		((cid.Field == cidRef.Field) || (cidRef.Field == "")) &&
		((cid.Type == cidRef.Type) || (cidRef.Type == "")) &&
		((cid.ValueMatch == cidRef.ValueMatch) || (cidRef.ValueMatch == "")) &&
		(cidRef.Kind == cid.Kind)
}

// equalNewFormat returns true if cidRef's fields are equal to cid in the new
// code identifier format.
//
//gocyclo:ignore
func (cid *ParsedCodeIdentifier) equalNewFormat(cidRef ParsedCodeIdentifier) bool {
	if cid == nil || !isNewFormat(*cid) {
		return false
	}
	switch cidRef.Target.Kind {
	case CallKind:
		// package and method must match
		if cidRef.Target.Package != cid.Target.Package {
			return false
		}
		if cidRef.Target.Method != cid.Target.Method {
			return false
		}
		// If cidRef (config cid) does not have any objects specified, then don't check them
		if len(cidRef.Target.Objects) > 0 {
			// every object in cid must be present in cidRef
			for _, obj := range cid.Target.Objects {
				found := false
				for _, objRef := range cidRef.Target.Objects {
					if obj.Kind == objRef.Kind &&
						obj.Name == objRef.Name &&
						obj.Type == objRef.Type &&
						obj.Index == objRef.Index {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
	}
	// Enclosing (calling context) does not need to be specified
	if cidRef.Enclosing.Package != "" {
		if cidRef.Enclosing.computedRegexs.packageRegex != nil {
			if !cidRef.Enclosing.computedRegexs.packageRegex.MatchString(cid.Enclosing.Package) {
				return false
			}
		} else {
			if cidRef.Enclosing.Package != cid.Enclosing.Package {
				return false
			}
		}
	}
	if cidRef.Enclosing.Method != "" {
		if cidRef.Enclosing.computedRegexs.methodRegex != nil {
			if !cidRef.Enclosing.computedRegexs.methodRegex.MatchString(cid.Enclosing.Method) {
				return false
			}
		} else {
			if cidRef.Enclosing.Method != cid.Enclosing.Method {
				return false
			}
		}
	}

	return true
}

// ExistsCid is true if there is some x in a such that f(x) is true.
// O(len(a))
func ExistsCid(a []ParsedCodeIdentifier, f func(identifier ParsedCodeIdentifier) bool) bool {
	for _, x := range a {
		if f(x) {
			return true
		}
	}
	return false
}

// FullMethodName returns the fully qualified name of the code identifier.
func (cid *ParsedCodeIdentifier) FullMethodName() string {
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
//
//gocyclo:ignore
func (cid *ParsedCodeIdentifier) MatchType(typ types.Type) bool {
	if cid == nil {
		return false
	}
	if typ == nil {
		return cid.Type == ""
	}
	if named, ok := typ.(*types.Named); ok {
		if named == nil { // extra check is needed because the *types.Named value can be nil, even if typ != nil
			return false
		}
		if named.Obj() != nil && named.Obj().Pkg() != nil {
			path := named.Obj().Pkg().Path()
			name := named.Obj().Name()
			if cid.computedRegexs != nil && cid.computedRegexs.packageRegex != nil && cid.computedRegexs.typeRegex != nil {
				if cid.computedRegexs.packageRegex.MatchString(path) && cid.computedRegexs.typeRegex.MatchString(name) {
					// be able to fall back to matching just the type
					return true
				}
			}
			if cid.Package == path && cid.Const == name {
				return true
			}
		}
	}
	if cid.computedRegexs != nil && cid.computedRegexs.typeRegex != nil {
		return cid.computedRegexs.typeRegex.MatchString(typ.String())
	}
	return cid.Type == typ.String()
}

// MatchPackageAndMethodWithCaller checks whether the function f matches the code identifier on the
// package and method fields and the context of the caller.
// It is safe to call with nil values.
func (cid *ParsedCodeIdentifier) MatchPackageAndMethodWithCaller(caller *ssa.Function, f *ssa.Function) bool {
	if cid == nil {
		return false
	}
	if caller != nil && cid.Context != "" &&
		cid.computedRegexs != nil && !cid.computedRegexs.contextRegex.MatchString(caller.String()) {
		return false
	}
	return cid.MatchPackageAndMethod(f)
}

// MatchPackageAndMethod checks whether the function f matches the code identifier on the package and method
// fields.
// It is safe to call with nil values.
func (cid *ParsedCodeIdentifier) MatchPackageAndMethod(f *ssa.Function) bool {
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
func (cid *ParsedCodeIdentifier) MatchInterface(f *ssa.Function) bool {
	if cid == nil {
		return false
	}
	if f == nil {
		return cid.Package == "" && cid.Interface == ""
	}

	pkg := lang.PackageNameFromFunction(f)
	if cid.computedRegexs != nil &&
		cid.computedRegexs.packageRegex != nil &&
		cid.computedRegexs.interfaceRegex != nil {
		return cid.computedRegexs.packageRegex.MatchString(pkg) &&
			cid.computedRegexs.interfaceRegex.MatchString(f.Type().String())
	}

	return cid.Package == pkg && cid.Interface == f.Type().String()
}

// MatchConst matches a named package-level constant to a code identifier.
func (cid *ParsedCodeIdentifier) MatchConst(c *ssa.NamedConst) bool {
	if cid == nil || c == nil {
		return false
	}

	pkg := c.Package().String()
	return cid.computedRegexs.packageRegex.MatchString(pkg) && cid.computedRegexs.constRegex.MatchString(c.Name())
}

// arRegex tries to compile to a regex, otherwise returns a regex that matches exactly the string
func asRegex(s string) *regexp.Regexp {
	r, err := regexp.Compile(s)
	if err == nil {
		return r
	}
	return asExactMatchRegex(s)
}

// asExactMatchRegex returns a regexp that matches exactly the string given as argument
func asExactMatchRegex(s string) *regexp.Regexp {
	r, err := regexp.Compile("^" + regexp.QuoteMeta(s) + "$")
	if err != nil {
		panic("Unexpected regex compilation error")
	}
	return r
}

// trimStartEndRegex trims ^ and $ at the beginning and end of a string if that string was meant to
// be a regex with exact matching
func trimStartEndRegex(s string) string {
	s1, ok := strings.CutSuffix(s, "$")
	if !ok {
		return s
	}
	s2, ok := strings.CutPrefix(s1, "^")
	if !ok {
		return s
	}
	return s2
}

// MatchAstCode matches an ast that has the same fields that the parsed code identifier
func (cid ParsedCodeIdentifier) MatchAstCode(a scanning.AstCode) bool {
	panic("UNIMPLEMENTED")
}

// MatchSsaCode matches  an ssa code identifier
func (cid ParsedCodeIdentifier) MatchSsaCode(p *pointer.Result, a scanning.SsaCode) bool {
	if a.Instr() != nil {
		_, ok := isEntrypointNode(p, a.Instr(), func(p ParsedCodeIdentifier) bool {
			return cid.EqualOnNonEmptyFields(p)
		})
		return ok
	}
	return false
}

// / IsEntrypointNode returns true if n matches a code identifier according to the predicate f
//
//gocyclo:ignore
func isEntrypointNode(pointer *pointer.Result, n ssa.Instruction,
	f func(ParsedCodeIdentifier) bool) (ParsedCodeIdentifier, bool) {
	switch node := (n).(type) {
	// Look for callees to functions that are considered entry points
	case *ssa.Call:
		if node == nil {
			return ParsedCodeIdentifier{}, false // inits cannot be entry points
		}

		parent := node.Parent()
		if !node.Call.IsInvoke() {
			if cid, ok := isFuncEntrypoint(node, parent, f); ok {
				return cid, true
			}
			if cid, ok := isAliasEntrypoint(pointer, node, f); ok {
				return cid, true
			}
			return ParsedCodeIdentifier{}, false
		}

		// For invoke also populate the receiver
		receiver := node.Call.Value.Name()
		methodName := node.Call.Method.Name()
		calleePkg := analysisutil.FindSafeCalleePkg(node.Common())
		if calleePkg.IsSome() {
			cid := ParsedCodeIdentifier{
				Context:    parent.String(),
				Package:    calleePkg.Value(),
				Method:     methodName,
				Receiver:   receiver,
				ValueMatch: n.String(),
			}
			if f(cid) {
				return cid, true
			}

			// Entrypoint could be one of the arguments: use the new code identifier format
			cids := newCodeIdentifierCall(node, calleePkg.Value(), methodName, parent)
			for _, cid := range cids {
				if f(cid) {
					return cid, true
				}
			}
		}
		return ParsedCodeIdentifier{}, false

	// Field accesses that are considered as entry points
	case *ssa.Field:
		fieldInfo := analysisutil.FieldFieldInfo(node)
		packageName, typeName, err := analysisutil.FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return ParsedCodeIdentifier{}, false
		}
		cid := ParsedCodeIdentifier{
			Context:    node.Parent().String(),
			Package:    packageName,
			Field:      fieldInfo.FieldName,
			Type:       typeName,
			ValueMatch: n.String(),
		}
		if f(cid) {
			return cid, true
		}
		return ParsedCodeIdentifier{}, false

	case *ssa.FieldAddr:
		fieldInfo := analysisutil.FieldAddrFieldInfo(node)
		packageName, typeName, err := analysisutil.FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return ParsedCodeIdentifier{}, false
		}
		cid := ParsedCodeIdentifier{
			Context:    node.Parent().String(),
			Package:    packageName,
			Field:      fieldInfo.FieldName,
			Type:       typeName,
			ValueMatch: n.String(),
		}
		if f(cid) {
			return cid, true
		}
		return ParsedCodeIdentifier{}, false

	// Allocations of data of a type that is an entry point
	case *ssa.Alloc:
		packageName, typeName, err := analysisutil.FindEltTypePackage(node.Type(), "%s")
		if err != nil {
			return ParsedCodeIdentifier{}, false
		}
		cid := ParsedCodeIdentifier{
			Context:    node.Parent().String(),
			Package:    packageName,
			Type:       typeName,
			ValueMatch: n.String(),
		}
		if f(cid) {
			return cid, true
		}
		return ParsedCodeIdentifier{}, false

	// Storing into a specific struct field
	case *ssa.Store:
		if fieldAddr, isFieldAddr := node.Addr.(*ssa.FieldAddr); isFieldAddr {
			fieldInfo := analysisutil.FieldAddrFieldInfo(fieldAddr)
			packageName, typeName, err := analysisutil.FindEltTypePackage(fieldAddr.X.Type(), "%s")
			if err != nil {
				return ParsedCodeIdentifier{}, false
			}
			cid := ParsedCodeIdentifier{
				Context:    node.Parent().String(),
				Package:    packageName,
				Field:      fieldInfo.FieldName,
				Type:       typeName,
				Kind:       "store",
				ValueMatch: n.String(),
			}
			if f(cid) {
				return cid, true
			}
			return ParsedCodeIdentifier{}, false
		}
		return ParsedCodeIdentifier{}, false

	// Channel receives can be sources
	case *ssa.UnOp:
		if node.Op == token.ARROW {
			packageName, typeName, err := analysisutil.FindEltTypePackage(node.X.Type(), "%s")
			if err != nil {
				return ParsedCodeIdentifier{}, false
			}
			cid := ParsedCodeIdentifier{
				Context:    node.Parent().String(),
				Package:    packageName,
				Type:       typeName,
				Kind:       "channel receive",
				ValueMatch: n.String(),
			}
			if f(cid) {
				return cid, true
			}
			return ParsedCodeIdentifier{}, false
		}
		return ParsedCodeIdentifier{}, false

	default:
		return ParsedCodeIdentifier{}, false
	}
}

// newCodeIdentifierCall returns a code identifier for each possible object in the call.
func newCodeIdentifierCall(
	node *ssa.Call,
	calleePkg string,
	methodName string,
	parent *ssa.Function,
) []ParsedCodeIdentifier {
	if parent == nil || parent.Package() == nil {
		return nil
	}

	var res []ParsedCodeIdentifier
	args := lang.GetArgs(node)
	params := lang.GetParams(node)
	for i, arg := range args {
		cid := ParsedCodeIdentifier{
			Target: Target{
				Kind:    CallKind,
				Package: calleePkg,
				Method:  methodName,
				Objects: []TargetObject{
					NewParamTargetObject(params[i], i, arg),
				},
			},
			Enclosing: CallingContext{
				Package: parent.Package().Pkg.Path(),
				Method:  parent.Name(),
			},
		}
		res = append(res, cid)
	}

	return res
}

// NewParamTargetObject returns the config.TargetObject corresponding to the parameter for arg at
// index idx.
func NewParamTargetObject(param lang.Param, idx int, arg ssa.Value) TargetObject {
	typ := arg.Type().String()
	if param.IsVariadic {
		// If the parameter type is variadic, the SSA form of the argument will be a slice
		// (`[]type`) instead of the `...type` form.
		typ = strings.TrimPrefix(typ, "[]")
		typ = "..." + typ
	}
	return TargetObject{
		Kind:  ArgumentKind,
		Name:  param.Var.Name(),
		Index: uint(idx),
		Type:  typ,
	}
}

// isFuncEntrypoint returns true if the actual function called matches an entrypoint.
func isFuncEntrypoint(
	node *ssa.Call,
	parent *ssa.Function,
	f func(ParsedCodeIdentifier) bool,
) (ParsedCodeIdentifier, bool) {
	funcValue := node.Call.Value.Name()
	calleePkg := analysisutil.FindSafeCalleePkg(node.Common())
	if calleePkg.IsSome() {
		cid := ParsedCodeIdentifier{Context: parent.String(), Package: calleePkg.Value(), Method: funcValue}
		if f(cid) {
			return cid, true
		}
		// Entrypoint could be one of the arguments: use the new code identifier format
		cids := newCodeIdentifierCall(node, calleePkg.Value(), funcValue, parent)
		for _, cid := range cids {
			if f(cid) {
				return cid, true
			}
		}
	}
	return ParsedCodeIdentifier{}, false
}

// isAliasEntrypoint returns true if any alias to node matches an entrypoint.
func isAliasEntrypoint(
	pointer *pointer.Result,
	node *ssa.Call,
	f func(ParsedCodeIdentifier) bool,
) (ParsedCodeIdentifier, bool) {
	if pointer == nil {
		return ParsedCodeIdentifier{}, false
	}
	ptr, hasAliases := pointer.Queries[node.Call.Value]
	if !hasAliases {
		return ParsedCodeIdentifier{}, false
	}
	for _, label := range ptr.PointsTo().Labels() {
		funcValue := label.Value().Name()
		funcPackage := analysisutil.FindValuePackage(label.Value())
		if funcPackage.IsSome() {
			cid := ParsedCodeIdentifier{Package: funcPackage.Value(), Method: funcValue}
			if f(cid) {
				return cid, true
			}
			// Entrypoint could be one of the arguments: use the new code identifier format
			cids := newCodeIdentifierCall(node, funcPackage.Value(), funcValue, label.Value().Parent())
			for _, cid := range cids {
				if f(cid) {
					return cid, true
				}
			}
		}
	}
	return ParsedCodeIdentifier{}, false
}
