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

package statefulrewrite_test

// This file contains code examples that show both correct
// and incorrect uses of reflect.Value with nil interface values.
//
// It does not actually test any functionality of the statefulrewrite package
// but was helpful in implementing it.

import (
	"fmt"
	"reflect"
	"testing"
)

// nil errors

func TestReflectNilErrorBad(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()

	err := nilErr()
	rerr := reflect.ValueOf(err)

	t.Log(rerr.IsNil())
}

func TestReflectNilErrorGood(t *testing.T) {
	err := nilErr()
	rerr := reflect.Zero(reflect.TypeOf((*error)(nil)).Elem())
	if err != nil {
		rerr = reflect.ValueOf(err)
	}

	if !rerr.IsNil() {
		t.Errorf("want nil reflect value, got: %v", rerr)
	}
}

func TestReflectErrorGood(t *testing.T) {
	err := errVal()
	rerr := reflect.Zero(reflect.TypeOf((*error)(nil)).Elem())
	if err != nil {
		rerr = reflect.ValueOf(err)
	}

	if rerr.IsNil() {
		t.Errorf("want non-nil reflect value, got: %v", rerr)
	}
}

func nilErr() error {
	return nil
}

func errVal() error {
	return fmt.Errorf("test")
}

// nil interfaces

func TestReflectNilIfaceBad(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()

	v := nilImpl()
	rv := reflect.ValueOf(v)

	t.Log(rv.IsNil())
}

func TestReflectNilIfaceGood(t *testing.T) {
	v := nilImpl()
	rv := reflect.Zero(reflect.TypeOf((*iface)(nil)).Elem())
	if v != nil {
		rv = reflect.ValueOf(v)
	}

	if !rv.IsNil() {
		t.Errorf("want nil reflect value, got: %v", rv)
	}
}

func TestReflectIfaceGood(t *testing.T) {
	v := implVal()
	v.do()
	rv := reflect.Zero(reflect.TypeOf((*iface)(nil)).Elem())
	if v != nil {
		rv = reflect.ValueOf(v)
	}

	if rv.IsNil() {
		t.Errorf("want non-nil reflect value, got: %v", rv)
	}
}

type iface interface {
	do()
}

type impl struct{}

func (*impl) do() {}

func nilImpl() iface {
	return nil
}

func implVal() iface {
	return &impl{}
}

// pointer value

func TestReflectNilPtrOk(t *testing.T) {
	var v *int
	rv := reflect.ValueOf(v)

	// does not panic on nil pointer values - no need to use reflect.Zero
	t.Log(rv.IsNil())
}
