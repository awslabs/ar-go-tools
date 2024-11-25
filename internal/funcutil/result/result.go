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

package result

import "fmt"

// A Result holds a value or an error.
type Result[T any] interface {
	// Value unwraps the result into a tuple
	Value() (*T, error)

	// IsErr returns true if the result represents an error
	IsErr() bool

	// IsOk returns true if the result is not an error
	IsOk() bool
}

type ok[T any] struct {
	value *T
}

func (s ok[T]) Value() (*T, error) { return s.value, nil }
func (s ok[T]) IsOk() bool         { return true }
func (s ok[T]) IsErr() bool        { return false }
func (s ok[T]) String() string     { return fmt.Sprintf("%v", s.value) }

// Ok creates a result value
func Ok[T any](x *T) Result[T] {
	return ok[T]{x}
}

type err[T any] struct {
	value error
}

func (s err[T]) ValueOr(defaultVal T) T { return defaultVal }
func (s err[T]) Value() (*T, error)     { return nil, s.value }
func (s err[T]) IsOk() bool             { return false }
func (s err[T]) IsErr() bool            { return true }
func (s err[T]) String() string         { return fmt.Sprintf("error: %s", s.value) }

// Err creates an error value
func Err[T any](e error) Result[T] {
	return err[T]{e}
}

// Bind is like the bind operation for the result monad
func Bind[T any, S any](v Result[T], f func(*T) Result[S]) Result[S] {
	if v.IsOk() {
		actual, _ := v.Value()
		return f(actual)
	}
	_, actualErr := v.Value()
	return err[S]{actualErr}

}

// Map is like the map operation for the result monad
func Map[T any, S any](v Result[T], f func(*T) *S) Result[S] {
	if v.IsOk() {
		actual, _ := v.Value()
		return Ok[S](f(actual))
	}
	_, actualErr := v.Value()
	return Err[S](actualErr)
}

// Do applies f to the content of the result if the result is ok
func Do[T any](v Result[T], f func(*T)) {
	if v.IsOk() {
		actual, _ := v.Value()
		f(actual)
	}
}
