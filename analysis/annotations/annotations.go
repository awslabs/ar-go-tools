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
	"regexp"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"golang.org/x/tools/go/ssa"
)

const annotationPrefix = "//argot:"

// AnnotationKind characterizes the kind of annotations that can be used in the program.
type AnnotationKind = int

const (
	// Sink is the kind of @Sink(...) annotations.
	Sink AnnotationKind = iota
	// Source is the kind of @Source(...) annotations
	Source AnnotationKind = iota
	// Sanitizer is the kind of @Sanitizer(...) annotations
	Sanitizer AnnotationKind = iota
)

// sourceRegex matches an annotation of the form @Source(id1, id2 meta2, ...)
// where the "argument" is either an identifier (e.g. id) or an identifier with
// associated "metadata" (e.g. id call:example1->call:helper->call:example1$1).
var sourceRegex = regexp.MustCompile(`.*@Source\(((?:\s*(\w|(\w\s+[a-zA-Z0-9$:\->]+\s*))\s*,?)+)\)`)

// sinkRegex matches annotations of the form @Sink(id1, id2, id3)"
var sinkRegex = regexp.MustCompile(`.*@Sink\(((?:\s*\w\s*,?)+)\)`)

// sanitizerRegex matches annotations of the form @Sanitizer(id1, id2, id3)"
var sanitizerRegex = regexp.MustCompile(`.*@Sanitizer\(((?:\s*\w\s*,?)+)\)`)

var annotationKindParsers = map[AnnotationKind]*regexp.Regexp{
	Sink:      sinkRegex,
	Source:    sourceRegex,
	Sanitizer: sanitizerRegex,
}

// Annotation contains the parsed content from an annotation component: the kind of the annotation and its arguments
// The syntax of an annotation is usually @<Kind>(<Comma separated contents).
type Annotation struct {
	// Kind of the annotation
	Kind AnnotationKind
	// Contents of the annotation (usually parsed from a comma-separated list of strings
	Contents []string
}

// A FunctionAnnotation groups the annotations relative to a function into main annotations for the entire function
// and parameter annotations for each parameter
type FunctionAnnotation struct {
	Mains  []Annotation
	Params map[*ssa.Parameter][]Annotation
}

// ProgramAnnotations groups all the program annotations together. Members of packages can be annotated:
// - function annotations are in Funcs
// - type annotations are in Types
// - constants annotations are in Consts
// - global variable annotations are in Globals
type ProgramAnnotations struct {
	// Funcs is the map of function annotations
	Funcs map[*ssa.Function]FunctionAnnotation
	// Types is the map of type annotations (TODO: implementation)
	Types map[*ssa.Type][]Annotation
	// Consts is the map of named constant annotations (TODO: implementation)
	Consts map[*ssa.NamedConst][]Annotation
	// Globals is the map of global variable annotations (TODO: implementation)
	Globals map[*ssa.Global][]Annotation
}

// Count returns the total number of annotations in the program
func (pa ProgramAnnotations) Count() int {
	c := 0
	for _, f := range pa.Funcs {
		c += len(f.Mains)
		for _, p := range f.Params {
			c += len(p)
		}
	}
	for _, cst := range pa.Consts {
		c += len(cst)
	}
	for _, cst := range pa.Types {
		c += len(cst)
	}
	for _, cst := range pa.Globals {
		c += len(cst)
	}
	return c
}

// LoadAnnotations loads annotations from a list of packages by inspecting the syntax of each element in the
// packages. If syntax is not provided, no annotation will be loaded (you should build the program with the syntax
// for the annotations to work).
// Returns an error when some annotation could not be loaded (instead of silently skipping). Those errors should
// be surfaced to the user, since it is the only way they can correct their annotations. The loading function
// will also print warnings when some syntactic components of the comments look like they should be an annotation.
func LoadAnnotations(logger *config.LogGroup, packages []*ssa.Package) (ProgramAnnotations, error) {
	annotations := ProgramAnnotations{
		Funcs:   map[*ssa.Function]FunctionAnnotation{},
		Types:   map[*ssa.Type][]Annotation{},
		Consts:  map[*ssa.NamedConst][]Annotation{},
		Globals: map[*ssa.Global][]Annotation{},
	}
	for _, pkg := range packages {
		for _, m := range pkg.Members {
			switch member := m.(type) {
			case *ssa.Function:
				functionAnnotation, err := parseFunctionAnnotations(logger, member)
				if err != nil {
					return annotations, err
				}
				annotations.Funcs[member] = functionAnnotation
			}
		}
	}
	return annotations, nil
}

func parseFunctionAnnotations(looger *config.LogGroup, function *ssa.Function) (FunctionAnnotation, error) {
	var doc *ast.CommentGroup
	declSyntax, isDeclSyntax := function.Syntax().(*ast.FuncDecl)
	if isDeclSyntax {
		doc = declSyntax.Doc
	}

	if doc == nil {
		return FunctionAnnotation{}, nil
	}

	annotations := FunctionAnnotation{
		Mains:  []Annotation{},
		Params: map[*ssa.Parameter][]Annotation{},
	}
	for _, comment := range doc.List {
		if strings.HasPrefix(comment.Text, annotationPrefix) {
			annotationContent := strings.Split(strings.TrimSpace(strings.TrimPrefix(comment.Text, annotationPrefix)), " ")
			if len(annotationContent) <= 1 {
				continue
			}
			switch annotationContent[0] {
			case "param":
				err := parseParamAnnotation(function, annotationContent, &annotations, comment)
				if err != nil {
					return annotations, err
				}
			case "function":
				annotationGroup, err := parseAnnotationContent(annotationContent)
				if err != nil {
					return annotations, err
				}
				annotations.Mains = append(annotations.Mains, annotationGroup...)
			}
		} else if strings.Contains(comment.Text, "argot") {
			looger.Warnf("possible annotation mistake: %s has \"argot\" but doesn't start with //argot:",
				comment.Text)
		}
	}
	return annotations, nil
}

func parseParamAnnotation(function *ssa.Function, annotationContent []string,
	annotations *FunctionAnnotation, comment *ast.Comment) error {
	paramName := annotationContent[1]
	foundParam := false
	for _, param := range function.Params {
		if param.Name() == paramName {
			foundParam = true
			if _, ok := annotations.Params[param]; !ok {
				annotations.Params[param] = []Annotation{}
			}
			paramAnnotations, err := parseAnnotationContent(annotationContent)
			if err != nil {
				return err
			}
			annotations.Params[param] = append(annotations.Params[param], paramAnnotations...)
		}
	}
	if !foundParam {
		return fmt.Errorf("could not find parameter %s in function %s for annotation %s",
			paramName, function.String(), comment.Text)
	}
	return nil
}

func parseAnnotationContent(annotationContent []string) ([]Annotation, error) {
	var parsedAnnotations []Annotation
	contents := strings.Join(annotationContent, " ")
	for kind, kindRegexp := range annotationKindParsers {
		idents := kindRegexp.FindStringSubmatch(contents)
		if len(idents) > 1 {
			parsedAnnotations = append(parsedAnnotations, Annotation{Kind: kind, Contents: parseAnnotationArgs(idents)})
		}
	}
	return parsedAnnotations, nil
}

func parseAnnotationArgs(a []string) []string {
	return strings.Split(a[1], ",")
}
