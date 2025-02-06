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

package statefulrewrite

import (
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"github.com/awslabs/ar-go-tools/internal/shims"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// StatefulRewritesOverlayTransformSpec contains the information necessary to perform the stateful rewrites.
// Currently, the only rewrite the the elimination of (reflect.Value).Call instances given an instance of
// an actuall struct with methods (class-like object).
type StatefulRewritesOverlayTransformSpec struct {
	RefelctValueCallInstanceCid config.CodeIdentifier
}

// StatefulRewritesOverlayTransform transforms the overlay in the config state by building
// the program, computing the necessary stateful rewrites, and setting the overlay in the
// config state with the appropriate rewritten files.
func StatefulRewritesOverlayTransform(c *config.State, spec StatefulRewritesOverlayTransformSpec) result.Result[config.State] {
	c.Logger.Infof("Applying rewrites")

	// Build a pointer state
	state, err := loadprogram.NewState(c).Value()
	cfg := findReflectValueCallToRewrite(state, spec.RefelctValueCallInstanceCid)
	if cfg.IsNone() {
		return result.Ok(c)
	}
	newOverlayElements := RewriteCallsToReflectValueCall(state, cfg.Value())
	if newOverlayElements == nil {
		return result.Ok(c)
	}

	if err != nil {
		return result.Err[config.State](err)
	}

	for fileName, fileContents := range newOverlayElements {
		c.Logger.Infof("overlay \"%s\"", fileName)
		c.Logger.Infof("File contents:\n%s", fileContents)
	}

	if c.Overlay == nil {
		c.Overlay = make(map[string][]byte)
	}

	for k, v := range newOverlayElements {
		c.Overlay[k] = v
	}

	return result.Ok(c)
}

func findReflectValueCallToRewrite(state *loadprogram.State, ci config.CodeIdentifier) funcutil.Optional[ReflectValueCallRewriterSpec] {
	implTypes, ok := FindImpl(state, ci)
	if !ok {
		state.Logger.Infof("No rewriting strategies applicable.")
		return funcutil.None[ReflectValueCallRewriterSpec]()
	}
	return funcutil.Some[ReflectValueCallRewriterSpec](ReflectValueCallRewriterSpec{
		Cid:          ci,
		ReceiverType: implTypes[0],
	})
}

// FindImpl returns the types of the arguments of the functions identified by the code identifier. The
// returned type is either a named type or a pointer to a named type.
func FindImpl(s *loadprogram.State, ci config.CodeIdentifier) ([]lang.MaybeRefNamedType, bool) {
	seen := make(map[lang.MaybeRefNamedType]struct{})
	for f := range ssautil.AllFunctions(s.Program) {
		lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				return
			}
			if call.Common().IsInvoke() {
				return
			}

			callee := call.Common().StaticCallee()
			if callee == nil {
				return
			}
			pkg := lang.PackageNameFromFunction(callee)

			if pkg == "" || (pkg != ci.Package && ci.Package != "") {
				return
			}
			if callee.Name() != ci.Method {
				return
			}

			implObj := lang.GetArgs(call)[0]
			actualObj := lang.ExtractInterfaceValueArg(implObj)
			actualObjTyp := actualObj.Type()
			isPtr := false
			possiblyNamedTy := actualObjTyp
			if ptrTy, ok := actualObjTyp.(*types.Pointer); ok {
				isPtr = true
				possiblyNamedTy = ptrTy.Elem()
			}
			if tNamed, ok := possiblyNamedTy.(*types.Named); ok {
				seen[lang.MaybeRefNamedType{IsRef: isPtr, Named: tNamed, Actual: actualObjTyp}] = struct{}{}
			}

		})
	}

	if len(seen) == 0 {
		return nil, false
	}

	return shims.Keys(seen), true
}
