package functional

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

// Contains returns true when there is some y in slice a such that x == y
func Contains[T comparable](a []T, x T) bool {
	return Exists(a, func(y T) bool { return x == y })
}
