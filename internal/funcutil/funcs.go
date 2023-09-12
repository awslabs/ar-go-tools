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

// First returns the first of two arguments
func First[T any](x T, _ T) T { return x }

// Second returns the first of two arguments
func Second[T any](_ T, y T) T { return y }

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
