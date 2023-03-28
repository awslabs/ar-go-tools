package functional

import (
	"sort"

	"golang.org/x/exp/constraints"
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
func Iter[T any](a []T, f func(T) T) {
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

// Exists returns true when there exists some x in slice a such that f(x), otherwise false.
func Exists[T any](a []T, f func(T) bool) bool {
	for _, x := range a {
		if f(x) {
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

func Reverse[T any](a []T) {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
}
