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

package annotations

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/ssa"
)

const annotationPrefix = "//argot:"

// AnnotationKind characterizes the kind of annotations that can be used in the program.
type AnnotationKind = int

const (
	// Sink is the kind of Sink(...) annotations.
	Sink AnnotationKind = iota
	// Source is the kind of Source(...) annotations
	Source
	// Sanitizer is the kind of Sanitizer(...) annotations
	Sanitizer
	// SetOptions is the kind of SetOptions(...) annotations
	SetOptions
	// Ignore is an empty annotation for a line
	Ignore
)

// AnyTag is the special tag used to match any other tag
const AnyTag = "_"

// TargetSpecifier is the type of target specifiers in the annotations: an annotation is of the shape
// "//argot:<target specifier> <target specifier arguments>* <annotations>
type TargetSpecifier = string

const (
	// ParamTarget is the specifier for function parameter targets
	ParamTarget TargetSpecifier = "param"
	// FunctionTarget is the specifier for function targets
	FunctionTarget TargetSpecifier = "function"
	// IgnoreTarget is the specifier for ignore targets
	IgnoreTarget TargetSpecifier = "ignore"
	// ConfigTarget is the specifier for config targets
	ConfigTarget TargetSpecifier = "config"
)

// sourceRegex matches an annotation of the form @Source(id1, id2 meta-2, ...)
var sourceRegex = regexp.MustCompile(`.*Source\(((?:\s*[\w\-]+\s*,?)+)\)`)

// sinkRegex matches annotations of the form @Sink(id1, id2, id3)"
var sinkRegex = regexp.MustCompile(`.*Sink\(((?:\s*[\w\-]+\s*,?)+)\)`)

// sanitizerRegex matches annotations of the form @Sanitizer(id1, id2, id3)"
var sanitizerRegex = regexp.MustCompile(`.*Sanitizer\(((?:\s*[\w\-]+\s*,?)+)\)`)

// setOptionsRegex matches annotations of the form @Sanitizer(id1, id2, id3)"
var setOptionsRegex = regexp.MustCompile(`.*SetOptions\(((?:\s*[\w\-]+=[\w\-]+\s*,?)+)\)`)

var annotationKindParsers = map[AnnotationKind]*regexp.Regexp{
	Sink:       sinkRegex,
	Source:     sourceRegex,
	Sanitizer:  sanitizerRegex,
	SetOptions: setOptionsRegex,
}

// Annotation contains the parsed content from an annotation component: the kind of the annotation and its arguments
// The syntax of an annotation is usually <Kind>(<Comma separated contents>).
type Annotation struct {
	// Kind of the annotation
	Kind AnnotationKind
	// Tags of the annotation (usually parsed from a comma-separated list of strings)
	Tags []string
}

// IsMatchingAnnotation returns true when the annotation matches the kind and tag provided.
// Returns true when the kinds are equal and either:
// - the tag provided is _
// - the annotation has a tag _
// - the annotation's tags contains the provided tag
func (a Annotation) IsMatchingAnnotation(kind AnnotationKind, tag string) bool {
	return a.Kind == kind && (tag == AnyTag || (len(a.Tags) > 0 && a.Tags[0] == AnyTag) || slices.Contains(a.Tags, tag))
}

// LinePos is a simple line-file position indicator.
type LinePos struct {
	Line int
	File string
}

// NewLinePos returns a LinePos from a token position. The column and offset are abstracted away.
func NewLinePos(pos token.Position) LinePos {
	return LinePos{
		Line: pos.Line,
		File: pos.Filename,
	}
}

func (l LinePos) String() string {
	return l.File + ":" + strconv.Itoa(l.Line)
}

// A FunctionAnnotation groups the annotations relative to a function into main annotations for the entire function
// and parameter annotations for each parameter
type FunctionAnnotation struct {
	mains       []Annotation
	params      map[*ssa.Parameter][]Annotation
	contentKeys map[string]bool
}

func (fa FunctionAnnotation) collectContentKeys() {
	for _, mainAnnot := range fa.mains {
		for _, key := range mainAnnot.Tags {
			fa.contentKeys[key] = true
		}
	}
	for _, paramAnnot := range fa.params {
		for _, annots := range paramAnnot {
			for _, key := range annots.Tags {
				fa.contentKeys[key] = true
			}
		}
	}
}

// ContentKeys returns the content keys in the annotations
func (fa FunctionAnnotation) ContentKeys() map[string]bool {
	return fa.contentKeys
}

// Mains returns the main annotations of the function
func (fa FunctionAnnotation) Mains() []Annotation {
	return fa.mains
}

// Params returns the map of parameters to annotations in the function
func (fa FunctionAnnotation) Params() map[*ssa.Parameter][]Annotation {
	return fa.params
}

// ProgramAnnotations groups all the program annotations together. Members of packages can be annotated:
// - function annotations are in Funcs
// - type annotations are in Types
// - constants annotations are in Consts
// - global variable annotations are in Globals
type ProgramAnnotations struct {
	// Configs is the map of configuration annotations, mapping problem tags to config settings
	Configs map[string]map[string]string
	// Funcs is the map of function annotations
	Funcs map[*ssa.Function]FunctionAnnotation
	// Types is the map of type annotations (TODO: implementation)
	Types map[*ssa.Type][]Annotation
	// Consts is the map of named constant annotations (TODO: implementation)
	Consts map[*ssa.NamedConst][]Annotation
	// Globals is the map of global variable annotations (TODO: implementation)
	Globals map[*ssa.Global][]Annotation
	// Positional is the map of line-file location to annotations that are not attached to a specific construct.
	// There can be only one annotation per line.
	Positional map[LinePos]Annotation
}

// IsIgnoredPos returns true when the given position is on the same line as an //argot:ignore annotation.
func (pa ProgramAnnotations) IsIgnoredPos(pos token.Position, tag string) bool {
	if posAnnot, hasPosAnnot := pa.Positional[NewLinePos(pos)]; hasPosAnnot {
		return posAnnot.Kind == Ignore && (posAnnot.Tags[0] == tag || posAnnot.Tags[0] == AnyTag)
	}
	return false
}

// Count returns the total number of annotations in the program
func (pa ProgramAnnotations) Count() int {
	c := 0
	pa.Iter(func(_ Annotation) { c += 1 })
	return c
}

// Iter iterates over all annotations in the program.
func (pa ProgramAnnotations) Iter(fx func(a Annotation)) {
	for _, f := range pa.Funcs {
		funcutil.Iter(f.mains, fx)
		for _, p := range f.params {
			funcutil.Iter(p, fx)
		}
	}
	for _, cst := range pa.Consts {
		funcutil.Iter(cst, fx)
	}
	for _, cst := range pa.Types {
		funcutil.Iter(cst, fx)
	}
	for _, cst := range pa.Globals {
		funcutil.Iter(cst, fx)
	}
	for _, cst := range pa.Positional {
		fx(cst)
	}
}

// CompleteFromSyntax takes a set of program annotations and adds additional non-ssa linked annotations
// to the annotations
func (pa ProgramAnnotations) CompleteFromSyntax(logger *config.LogGroup, fset *token.FileSet, files []*ast.File) {
	for _, astFile := range files {
		pa.loadPackageDocAnnotations(astFile.Doc)
		for _, comments := range astFile.Comments {
			for _, comment := range comments.List {
				if annotationContents := extractAnnotation(comment); annotationContents != nil {
					pa.loadFileAnnotations(logger, comment, annotationContents, fset.Position(comment.Pos()))
				}
			}
		}
	}
}

// LoadAnnotations loads annotations from a list of packages by inspecting the syntax of each element in the
// packages. If syntax is not provided, no annotation will be loaded (you should build the program with the syntax
// for the annotations to work).
// Returns an error when some annotation could not be loaded (instead of silently skipping). Those errors should
// be surfaced to the user, since it is the only way they can correct their annotations. The loading function
// will also print warnings when some syntactic components of the comments look like they should be an annotation.
func LoadAnnotations(logger *config.LogGroup, packages []*ssa.Package) (ProgramAnnotations, error) {
	annotations := ProgramAnnotations{
		Configs:    map[string]map[string]string{},
		Funcs:      map[*ssa.Function]FunctionAnnotation{},
		Types:      map[*ssa.Type][]Annotation{},
		Consts:     map[*ssa.NamedConst][]Annotation{},
		Globals:    map[*ssa.Global][]Annotation{},
		Positional: map[LinePos]Annotation{},
	}
	for _, pkg := range packages {
		for _, m := range pkg.Members {
			switch member := m.(type) {
			case *ssa.Function:
				functionAnnotation, err := parseFunctionAnnotations(logger, member)
				if err != nil {
					return annotations, err
				}
				if len(functionAnnotation.contentKeys) > 0 {
					annotations.Funcs[member] = functionAnnotation
				}
			}
		}
	}
	return annotations, nil
}

func extractAnnotation(comment *ast.Comment) []string {
	if strings.HasPrefix(comment.Text, annotationPrefix) {
		return strings.Split(strings.TrimSpace(strings.TrimPrefix(comment.Text, annotationPrefix)), " ")
	}
	return nil
}

func parseFunctionAnnotations(logger *config.LogGroup, function *ssa.Function) (FunctionAnnotation, error) {
	var doc *ast.CommentGroup
	declSyntax, isDeclSyntax := function.Syntax().(*ast.FuncDecl)
	if isDeclSyntax {
		doc = declSyntax.Doc
	}

	if doc == nil {
		return FunctionAnnotation{}, nil
	}

	annotations := FunctionAnnotation{
		mains:       []Annotation{},
		params:      map[*ssa.Parameter][]Annotation{},
		contentKeys: map[string]bool{},
	}
	for _, comment := range doc.List {
		if annotationContent := extractAnnotation(comment); annotationContent != nil {
			if len(annotationContent) <= 1 {
				continue
			}
			switch annotationContent[0] {
			case ParamTarget:
				err := parseParamAnnotation(function, annotationContent, &annotations, comment)
				if err != nil {
					return annotations, err
				}
			case FunctionTarget:
				annotationGroup, err := parseAnnotationContent(annotationContent)
				if err != nil {
					return annotations, err
				}
				annotations.mains = append(annotations.mains, annotationGroup...)
			case IgnoreTarget:
				logger.Warnf("argot:ignore has no effect as function annotation.")
			}
		} else if strings.Contains(comment.Text, "argot") {
			logger.Warnf("possible annotation mistake: %s has \"argot\" but doesn't start with //argot:",
				comment.Text)
		}
	}
	annotations.collectContentKeys()
	return annotations, nil
}

func (pa ProgramAnnotations) loadPackageDocAnnotations(doc *ast.CommentGroup) {
	// TODO: implementation
}

// loadFileAnnotations loads the annotation that are not tied to a specific ssa node. This includes:
// - config annotations
// - positional annotations
func (pa ProgramAnnotations) loadFileAnnotations(logger *config.LogGroup, comment *ast.Comment, annotationContents []string, position token.Position) {
	if len(annotationContents) == 0 {
		logger.Warnf("ignoring argot annotation: %s at %s: no arguments", comment.Text, position)
		return
	}

	if len(annotationContents) == 1 {
		logger.Warnf("no tag specified in argot annotation: %s at %s", comment.Text, position)
		// add an empty tag if none are specified
		annotationContents = append(annotationContents, "")
	}

	switch annotationContents[0] {
	case ConfigTarget:
		pa.loadConfigTargetAnnotation(logger, annotationContents, position)
	case IgnoreTarget:
		pa.addIgnoreLineAnnotation(position, annotationContents)
	default:
		logger.Warnf("ignoring argot annotation: %s at %s: invalid contents: %v", comment.Text, position, annotationContents)
	}
}

// addIgnoreLineAnnotation adds a Ignore annotation at the position's line
func (pa ProgramAnnotations) addIgnoreLineAnnotation(position token.Position, annotationContents []string) {
	pa.Positional[NewLinePos(position)] = Annotation{
		Kind: Ignore,
		Tags: []string{annotationContents[1]}, // only the tag is used
	}
}

// loadConfigTargetAnnotation loads a config annotation. Config annotations look like
// "//argot:config tag SetOptions(option-name-1=value1,option-name-2=value2)" and are always linked to a specific problem
// tag.
func (pa ProgramAnnotations) loadConfigTargetAnnotation(logger *config.LogGroup, annotationContents []string, position token.Position) {
	if len(annotationContents) <= 2 {
		logger.Warnf("argot:config expects a target tag and one or more SetOptions")
		logger.Warnf("a comment is likely missing something at %s", position)
		return
	}
	targetTag := annotationContents[1]
	if _, present := pa.Configs[targetTag]; !present {
		pa.Configs[targetTag] = map[string]string{}
	}
	idents := setOptionsRegex.FindStringSubmatch(strings.Join(annotationContents[2:], " "))
	if len(idents) > 1 {
		for _, arg := range parseAnnotationArgs(idents) {
			// split something that should be option-name=option-value
			argc := strings.Split(arg, "=")
			if len(argc) < 2 {
				logger.Warnf(
					"argot:config comment ignored because SetOptions argument is not option-name=value at %s",
					position)
				return
			}
			if prevValue, isSet := pa.Configs[targetTag][argc[0]]; isSet {
				logger.Warnf("argot:config option for %q already set to %q, ignoring annotation at %s",
					argc[0], prevValue, position)
			} else {
				pa.Configs[targetTag][argc[0]] = argc[1]
				logger.Debugf("set option %q to %q for problem tagged %q (annotation at %s)",
					argc[0], argc[1], targetTag, position)
			}
		}
	} else {
		logger.Warnf("argot:config annotation encountered without matching SetOptions at %s", position)
	}
	return
}

func parseParamAnnotation(function *ssa.Function, annotationContent []string,
	annotations *FunctionAnnotation, comment *ast.Comment) error {
	paramName := annotationContent[1]
	for _, param := range function.Params {
		if param.Name() == paramName {
			if _, ok := annotations.params[param]; !ok {
				annotations.params[param] = []Annotation{}
			}
			paramAnnotations, parseErr := parseAnnotationContent(annotationContent)
			if parseErr != nil {
				return parseErr
			}
			annotations.params[param] = append(annotations.params[param], paramAnnotations...)
			return nil
		}
	}
	// If the parameter hasn't been found, that's a mistake and the used should know
	return fmt.Errorf("could not find parameter %q in function %q for annotation %q",
		paramName, function.String(), comment.Text)
}

func parseAnnotationContent(annotationContent []string) ([]Annotation, error) {
	var parsedAnnotations []Annotation
	contents := strings.Join(annotationContent, " ")
	for kind, kindRegexp := range annotationKindParsers {
		idents := kindRegexp.FindStringSubmatch(contents)
		if len(idents) > 1 {
			parsedAnnotations = append(parsedAnnotations, Annotation{Kind: kind, Tags: parseAnnotationArgs(idents)})
		}
	}
	return parsedAnnotations, nil
}

func parseAnnotationArgs(a []string) []string {
	if len(a) < 2 {
		return []string{}
	}
	return funcutil.Map(strings.Split(a[1], ","), func(s string) string { return strings.TrimSpace(s) })
}
