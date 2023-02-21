package functional

// Compose (f,g) returns a function h: x -> f(g(x))
func Compose[T any, S any, R any](f func(T) S, g func(S) R) func(T) R {
	return func(x T) R { return g(f(x)) }
}
