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

package funcutil

import (
	"sort"
	"sync"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
)

// Merge merges the two maps into the first map.
// if x is in b but not in a, then a[x] := b[x]
// if x in both in a and b, then a[x] := both(a[x], b[x])
// @mutates a
func Merge[T comparable, S any](a map[T]S, b map[T]S, both func(x S, y S) S) {
	for x, yb := range b {
		ya, ina := a[x]
		if ina {
			a[x] = both(ya, yb)
		} else {
			a[x] = yb
		}
	}
}

// Union returns the union of map-represented sets a and b. This mutates map a
// @mutates a
func Union[T comparable](a map[T]bool, b map[T]bool) map[T]bool {
	Merge(a, b, func(a bool, b bool) bool { return a || b })
	return a
}

// Iter iterates over all elements in the slice and call the function on that element.
func Iter[T any](a []T, f func(T)) {
	for _, x := range a {
		f(x)
	}
}

// MapInPlace iterates over all elements in the slice and call the function on that element to update it.
func MapInPlace[T any](a []T, f func(T) T) {
	for i, x := range a {
		a[i] = f(x)
	}
}

// Map returns a new slice b such for any i <= len(a), b[i] = f(a[i])
func Map[T any, S any](a []T, f func(T) S) []S {
	var b []S
	for _, x := range a {
		b = append(b, f(x))
	}
	return b
}

// MapValues returns a new slice b such for any i <= len(a), b[i] = f(a[i])
func MapValues[T comparable, S any](a map[T]S, f func(S) S) map[T]S {
	for k, x := range a {
		a[k] = f(x)
	}
	return a
}

// elt is a helper struct to ensure that MapParallel maintains element order.
type elt[T any] struct {
	idx int // index in original slice
	x   T
}

// MapParallel is a parallel version of Map using numRoutines goroutines.
func MapParallel[T any, S any](a []T, f func(T) S, numRoutines int) []S {
	in := make(chan elt[T])
	go func() {
		defer close(in)
		for i, x := range a {
			in <- elt[T]{i, x}
		}
	}()

	out := make(chan elt[S])
	wg := &sync.WaitGroup{}
	if numRoutines <= 0 {
		numRoutines = 1
	}

	wg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func() {
			defer wg.Done()
			for x := range in {
				out <- elt[S]{x.idx, f(x.x)}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	xs := make([]elt[S], 0, len(out))
	for x := range out {
		xs = append(xs, x)
	}

	res := make([]S, len(xs))
	for _, x := range xs {
		res[x.idx] = x.x
	}

	return res
}

// Exists returns true when there exists some x in slice a such that f(x), otherwise false.
func Exists[T any](a []T, f func(T) bool) bool {
	for _, x := range a {
		if f(x) {
			return true
		}
	}
	return false
}

// ExistsInMap returns true when there exists some k,x in map a such that f(k,x), otherwise false.
func ExistsInMap[K comparable, T any](a map[K]T, f func(K, T) bool) bool {
	for k, x := range a {
		if f(k, x) {
			return true
		}
	}
	return false
}

// FindMap returns Some(f(x)) when there exists some x in slice a such that p(f(x)), otherwise None.
func FindMap[T any, R any](a []T, f func(T) R, p func(R) bool) Optional[R] {
	for _, x := range a {
		b := f(x)
		if p(b) {
			return Some(b)
		}
	}
	return None[R]()
}

// Contains returns true when there is some y in slice a such that x == y
func Contains[T comparable](a []T, x T) bool {
	return Exists(a, func(y T) bool { return x == y })
}

// Set takes an array of elements and returns a set of those elements, represented as a map from
// elements to empty struct
func Set[T comparable](a []T) map[T]struct{} {
	set := map[T]struct{}{}
	for _, x := range a {
		set[x] = struct{}{}
	}
	return set
}

// SetToOrderedSlice converts a set represented as a map from elements to booleans into a slice.
// Sorts the result in increasing order
func SetToOrderedSlice[T constraints.Ordered](set map[T]bool) []T {
	var s []T
	for r, b := range set {
		if b {
			s = append(s, r)
		}
	}
	sort.Slice(s, func(i int, j int) bool { return s[i] < s[j] })
	return s
}

// Reverse returns the reversed slice
func Reverse[T any](a []T) {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
}

// Retain removes all the key-value pairs in m where the key is not in keys.
func Retain[T comparable, R any](m map[T]R, keys []T) {
	maps.DeleteFunc(m, func(t T, r R) bool {
		return !Contains(keys, t)
	})
}
