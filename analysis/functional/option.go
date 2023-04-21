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

package functional

import (
	"fmt"
)

type Optional[T any] interface {
	// ValueOr returns the value of the optional if it is some value, otherwise the default value if it is none
	ValueOr(defaultVal T) T

	// Value returns the value or panics if it is none
	Value() T

	// IsSome returns true if the optional represents some value
	IsSome() bool

	// IsNone returns true is the optional is none
	IsNone() bool
}

type some[T any] struct {
	value T
}

func (s some[T]) ValueOr(_ T) T  { return s.value }
func (s some[T]) Value() T       { return s.value }
func (s some[T]) IsSome() bool   { return true }
func (s some[T]) IsNone() bool   { return false }
func (s some[T]) String() string { return fmt.Sprintf("%v", s.value) }

func Some[T any](x T) Optional[T] {
	return some[T]{x}
}

type none[T any] struct{}

func (s none[T]) ValueOr(defaultVal T) T { return defaultVal }
func (s none[T]) Value() T               { panic(s) }
func (s none[T]) IsSome() bool           { return false }
func (s none[T]) IsNone() bool           { return true }
func (s none[T]) String() string         { return "none" }

func None[T any]() Optional[T] {
	return none[T]{}
}

func MapOption[T any, S any](x Optional[T], f func(T) S) Optional[S] {
	if v, ok := x.(some[T]); ok {
		return some[S]{f(v.value)}
	} else {
		return none[S]{}
	}
}

func MaybeOr[T any](x Optional[T], s Optional[T]) Optional[T] {
	if _, ok := x.(some[T]); ok {
		return x
	} else {
		return s
	}
}

func BindOption[T any, S any](x Optional[T], f func(T) Optional[S]) Optional[S] {
	if v, ok := x.(some[T]); ok {
		return f(v.value)
	} else {
		return none[S]{}
	}
}
