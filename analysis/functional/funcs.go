package functional

// Compose (f,g) returns a function h: x -> f(g(x))
func Compose[T any, S any, R any](f func(T) S, g func(S) R) func(T) R {
	return func(x T) R { return g(f(x)) }
}

// Curry2 is for currying functions. with two arguments
func Curry2[T any, S any, R any](f func(T, S) R, x T) func(S) R {
	return func(s S) R { return f(x, s) }
}

// Curry3 is for currying functions. with three arguments
func Curry3[T any, S any, R any, Q any](f func(T, S, R) Q, x T) func(S, R) Q {
	return func(s S, r R) Q { return f(x, s, r) }
}
