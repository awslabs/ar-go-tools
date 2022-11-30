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

// Map iterates over all elements in the slice and call the function on that element.
func Map[T any](a []T, f func(T) T) {
	for i, x := range a {
		a[i] = f(x)
	}
}
