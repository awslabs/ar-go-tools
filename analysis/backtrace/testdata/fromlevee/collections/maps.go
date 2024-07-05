// Copyright 2020 Google LLC
// Modifications Copyright Amazon.com, Inc. or its affiliates
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

package collections

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

func TestMapLiteralContainingSourceKeyIsTainted(s core.SourceT) {
	m := map[core.SourceT]string{s: "ok"}
	core.Sink(m) // @Sink(map1)
}

func TestMapLiteralContainingSourceValueIsTainted(s core.SourceT) {
	m := map[string]core.SourceT{"source": s}
	core.Sink(m) // @Sink(map2)
}

func TestMapIsTaintedWhenSourceIsInserted(s core.SourceT) {
	m := map[core.SourceT]core.SourceT{}
	m[s] = s
	core.Sink(m) // @Sink(map3)
}

func TestTaintIsNotPropagatedwhenMapIsOverwritten(s core.SourceT) {
	m := map[string]interface{}{"source": s}
	core.Sink(m) // @Sink(map4)
	m = nil
	core.Sink(m)
}

func TestValueObtainedFromTaintedMapIsTainted(s core.SourceT) {
	m := map[interface{}]string{s: "source"}
	v := m[0]
	core.Sink(v) // @Sink(map5)
}

func TestMapRemainsTaintedWhenSourceIsDeleted(s core.SourceT) {
	m := map[interface{}]string{s: "source"}
	delete(m, s)
	core.Sink(m) // @Sink(map6)
}

func TestDeletingFromTaintedMapDoesNotTaintKey(key *string, sources map[*string]core.SourceT) {
	// The key needs to be a pointer parameter, because we don't traverse to non-pointer
	// arguments of a call, and we don't traverse to Allocs.
	delete(sources, key)
	core.Sink(key)
}

func TestMapUpdateWithTaintedValueDoesNotTaintTheKey(key string, value core.SourceT, sources map[string]core.SourceT) {
	sources[key] = value
	core.Sink(key)
}

func TestMapUpdateWithTaintedKeyDoesNotTaintTheValue(key core.SourceT, value string, sources map[core.SourceT]string) {
	sources[key] = value
	core.Sink(value)
}

func TestRangeOverMapWithSourceAsValue() {
	m := map[string]core.SourceT{"secret": core.Source2()} // @Source(map8)
	// loop over tainted data
	for k, s := range m {
		core.Sink(s) // @Sink(map8)
		core.Sink(k) // @Sink(map8) TODO: our analysis is not sensitive to key/values, but levee is
	}
}

func TestRangeOverMapWithSourceAsKey() {
	m := map[core.SourceT]string{core.Source2(): "don't sink me"} // @Source(map9)
	// branch over tainted data
	for src, str := range m {
		core.Sink(src) // @Sink(map9)
		core.Sink(str) // @Sink(map9) TODO: our analysis is not sensitive to key/values, but levee is
	}
}

func TestAllMap() {
	TestMapLiteralContainingSourceKeyIsTainted(core.Source2())   // @Source(map1)
	TestMapLiteralContainingSourceValueIsTainted(core.Source2()) // @Source(map2)
	TestMapIsTaintedWhenSourceIsInserted(core.Source2())         // @Source(map3)
	TestTaintIsNotPropagatedwhenMapIsOverwritten(core.Source2()) // @Source(map4)
	TestValueObtainedFromTaintedMapIsTainted(core.Source2())     // @Source(map5)
	TestMapRemainsTaintedWhenSourceIsDeleted(core.Source2())     // @Source(map6)

	key := "ok"
	sourceMap := map[*string]core.SourceT{&key: core.Source2()}
	TestDeletingFromTaintedMapDoesNotTaintKey(&key, sourceMap)

	sourceMap2 := map[string]core.SourceT{key: core.Source2()}
	TestMapUpdateWithTaintedValueDoesNotTaintTheKey(key, core.Source2(), sourceMap2)

	sourceMap3 := map[core.SourceT]string{core.Source2(): key}
	TestMapUpdateWithTaintedKeyDoesNotTaintTheValue(core.Source2(), key, sourceMap3)

	TestRangeOverMapWithSourceAsValue()
	TestRangeOverMapWithSourceAsKey()
}
