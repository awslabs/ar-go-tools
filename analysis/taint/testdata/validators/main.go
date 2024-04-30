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

package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

func source1() string {
	return "sensitive-data"
}

func sink1(s any) {
	fmt.Println(s)
}

func Validate(x string) bool {
	return x != "sensitive-data"
}

func gen(s *string) {
	*s = source1() // @Source(gen)
}

// Example 0: validator used a condition before calling sink

func validatorExample0() {
	x := source1() // @Source(ex0)
	if Validate(x) {
		sink1(x) // This has been validated!
	} else {
		sink1(x) // @Sink(ex0)
	}
}

func validatorExample0Bis() {
	var x string
	gen(&x)
	value := x // this is necessary to make sure the value validated is "owned"
	if Validate(value) {
		sink1(value) // This has been validated!
	} else {
		sink1(value) // @Sink(gen)
	}
}

func validatorExample0BisNegative() {
	var x string
	gen(&x)
	if Validate(x) { // x is loaded first then validated as a value
		sink1(x) // this is validated
	} else {
		sink1(x) // @Sink(gen)
	}
}

// Example 1: validator is used to clear value inside a conditional

func validatorExample1() {
	s := "ok"
	gen(&s)
	k := ""
	if rand.Int() > 10 {
		k = s
	} else {
		if !Validate(s) {
			k = ""
		}
	}
	sink1(k) // @Sink(gen) TODO: false alarm, but this is acceptable for now
}

// Example 2: validator is used to return before sink if negative

func validatorExample2() {
	s := "ok"
	gen(&s)
	if !Validate(s) {
		return
	}
	sink1(s) // This is validated
}

// Example 3: validator is used to assign value only when safe

func validatorExample3() {
	s := "ok"
	gen(&s)
	k := ""
	if Validate(s) {
		k = s
	}
	sink1(k) // @Sink(gen) TODO: flow sensitivity with variable reinitialized
}

// Example 4: validator is used inside a function being called

func pass(i int, x string) (bool, string) {
	r := strings.Clone(x) + strconv.Itoa(i)
	return Validate(r), r
}

func validatorExample4() {
	a := source1() // @Source(ex4)
	ok, b := pass(2, a)
	// branch on tainted data TODO: validators on part of the argument
	if ok {
		sink1(b) // @Sink(ex4) TODO: validators on part of the argument
	}
}

// Example 5: every element of a slice is validated

func validatorExample5() {
	a := make([]string, 10)
	for i := range a {
		a[i] = source1() // @Source(ex5)
	}
	b := make([]string, 10)
	for i := range b {
		if Validate(a[i]) {
			b[i] = a[i]
		}
	}
	sink1(b[0]) // @Sink(ex5) TODO: flow sensitivity
}

// Example 6: validate an entire struct when a field is tainted

type A struct {
	X int
	Y string
}

func Validate2(a A) bool {
	// branch on tainted data
	return a.X > 0 && Validate(a.Y)
}

func validatorExample6() {
	a1 := A{
		X: len(source1()), // @Source(ex6f1)
		Y: source1(),      // @Source(ex6f2)
	}
	sink1(strconv.Itoa(a1.X)) // @Sink(ex6f1)
	if Validate2(a1) {
		i, _ := strconv.Atoi(a1.Y)
		sink1(i) // @Sink(ex6f2) TODO: do we need flow-sensitive validation?
	}
}

// Example 7 : a validator that returns an error when data is not valid, data is validated when err == nil
// The sink is called when err == nil and when err != nil, and alarm is raised only in the first case.

func Validate3(a A) error {
	if a.X > 0 {
		return nil
	} else {
		return fmt.Errorf("error X field should be positive")
	}
}

func example7validateOnErrorWhenNotNil() {
	a1 := A{
		X: 0,
		Y: source1(), // @Source(s7)
	}
	if err := Validate3(a1); err != nil {
		sink1(a1) // @Sink(s7)
	}
	sink1(a1) // this is validated by a nil-check
}

// Example 8 : a validator that returns an error when data is not valid, data is validated when err == nil
// The sink is called when err != nil and err == nil but the branches are reverse compared to example7

func example8validateOnErrorWhenNil() {
	a1 := A{
		X: 0,
		Y: source1(), // @Source(s8)
	}
	if err := Validate3(a1); err == nil {
		sink1(a1)
	}
	sink1(a1) // @Sink(s8)
}

// Example 9: a validator that returns something + an error when data is not valid. The data is valid when
// the returned error is nil, and the validated data is what is passed to the validator

func example9validateOnLastErrorInTuple() {
	a1 := A{
		X: 0,
		Y: source1(), // @Source(s9)
	}
	if info, err := ValidateErr(a1); err != nil {
		fmt.Println(info)
		sink1(a1) // @Sink(s9)
	}
	sink1(a1)
}

func ValidateErr(a A) (string, error) {
	if a.X > 0 {
		return "ok", nil
	} else {
		return "bad", fmt.Errorf("error X field should be positive")
	}
}

// Example 10: a validator that returns something + a boolean that is true when data is valid.

func example10validateOnLastBoolInTuple() {
	a1 := A{
		X: 0,
		Y: source1(), // @Source(s10)
	}
	if info, ok := ValidateBool(a1); ok {
		fmt.Println(info)
		sink1(a1)
	}
	sink1(a1) // @Sink(s10)
}

func ValidateBool(a A) (string, bool) {
	if a.X > 0 {
		return "ok", true
	} else {
		return "bad", false
	}
}

// Example 11: a validator that returns something + an error when data is not valid. The data is valid when
// the returned error is nil, and the validated data is what is passed to the validator
// In this example, the validation is misused

func example11validateErrWrongCondition() {
	a1 := A{
		X: 0,
		Y: source1(), // @Source(s11)
	}
	if info, err := ValidateErr(a1); err == nil {
		fmt.Println(info)
	}
	sink1(a1) // @Sink(s11)
}

// Example 12: a validator that returns something + a boolean that is true when data is valid.
// The validator is misused in this example

func example12validateBoolWrongCondition() {
	a1 := A{
		X: 0,
		Y: source1(), // @Source(s12)
	}
	if info, ok := ValidateBool(a1); !ok {
		fmt.Println(info)
		sink1(a1) // @Sink(s12)
	}
}

// Example 13: a validator is used to validate some data, but data also flows from another source,
// which should raise an alarm.

func example13ValidateThenTaint() {
	x := source1() // @Source(ex13)
	y := source1() // @Source(ex13bis)
	if Validate(x) {
		sink1(x) // This has been validated!
		x = "(" + y + ")"
		sink1(x) // @Sink(ex13bis)
	} else {
		sink1(x) // @Sink(ex13)
	}
}

// Example 19: validate a parameter of the function
func example19ValidateFunctionParameter() {
	a1 := A{0, source1()} // @Source(ex19)
	validateThenSink(a1)
}

func validateThenSink(ax A) {
	dummyUsage(&(ax.Y))
	_, err := ValidateErr(ax)
	if err != nil {
		return
	}
	sink1(ax)
}

func dummyUsage(x *string) {
	fmt.Println(*x)
}

func main() {
	validatorExample0()
	validatorExample0Bis()
	validatorExample0BisNegative()
	validatorExample1()
	validatorExample2()
	validatorExample3()
	validatorExample4()
	validatorExample5()
	validatorExample6()
	example7validateOnErrorWhenNotNil()
	example8validateOnErrorWhenNil()
	example9validateOnLastErrorInTuple()
	example10validateOnLastBoolInTuple()
	example11validateErrWrongCondition()
	example12validateBoolWrongCondition()
	example13ValidateThenTaint()
	example14validateOnReference()
	example15validateOnReference2()
	example16validateOnReference3()
	example17validateOnReference4()
	example18validateOnFieldReference()
	example19ValidateFunctionParameter()
}
