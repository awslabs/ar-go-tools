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
	"time"
)

type IChecker interface {
	Check() bool
}

type G struct {
	x int
}

func (g G) Check() bool {
	return g.x == 0
}

func FooFunc(g G) {
	fmt.Println("FooFunc" + strconv.Itoa(g.x))
}

func FooPreCheck() bool {
	return rand.Int() > 10
}

func ResourceCheck() (bool, error) {
	if rand.Int() > 12 {
		return false, fmt.Errorf("err")
	}
	return true, nil
}

func callFooChecked() {
	b := FooPreCheck()
	if !b {
		return
	}
	FooFunc(G{})
}

func callFooCheckedWithInterface(g G) {
	if !g.Check() {
		return
	}
	FooFunc(g)
}

func callFooWrongChecked() {
	b := FooPreCheck()
	if b {
		return
	}
	FooFunc(G{}) // @InvalidCall(funcCond)
}

func callFooCheckedPathNoReturns() {
	b := FooPreCheck()
	if !b {
		fmt.Println("Should return!")
	}
	FooFunc(G{}) // @InvalidCall(funcCond)
}

func callFooDoubleChecked() {
	b := FooPreCheck()
	if !b {
		fmt.Println("Should return!")
	}
	c := FooPreCheck()
	if !c {
		return
	}
	FooFunc(G{})
}

func callFooUnChecked() {
	FooPreCheck()
	FooFunc(G{}) // @InvalidCall(funcCond)
}

func callFooResourceCheck() {
	b, e := ResourceCheck()
	if !b || e != nil {
		return
	}
	FooFunc(G{})
}

func callFooResourceCheckTwoConds() {
	b, e := ResourceCheck()
	if !b {
		return
	}
	if e != nil {
		return
	}
	FooFunc(G{})
}

func callFooResourceCheckTwoCondsRev() {
	b, e := ResourceCheck()
	if e != nil {
		return
	}
	if !b {
		return
	}
	FooFunc(G{})
}

func callFooResourceCheckTwoCondsWrong() {
	b, e := ResourceCheck()
	if e != nil {
		return
	}
	if !b {
		FooFunc(G{}) // @InvalidCall(funcCond)
	}
}

func callFooResourceCheckTwoCondsSwap() {
	b, e := ResourceCheck()
	if e != nil {
		return
	}
	if b {
		FooFunc(G{})
	}
}

func callFooCheckInLoop() {
	for i := 0; i < rand.Int(); i++ {
		b, e := ResourceCheck()
		if !b || e != nil {
			continue
		}
		FooFunc(G{})
	}
}

func callFooWrongCheckInLoop() {
	for i := 0; i < rand.Int(); i++ {
		b, e := ResourceCheck()
		if b || e != nil {
			return
		}
		FooFunc(G{}) // @InvalidCall(funcCond)
	}
}

func callFooCheckInLoopWithContinue() {
	for i := 0; i < rand.Int(); i++ {
		b, e := ResourceCheck()
		if !b || e != nil {
			continue
		}
		FooFunc(G{}) // Fine because of the continue statement
	}
}

func callFooCheckInLoopWithBreak() {
	for i := 0; i < rand.Int(); i++ {
		b, e := ResourceCheck()
		if !b || e != nil {
			break
		}
		FooFunc(G{}) // Fine because of the break statement
	}
}

func callFooCheckInLoopWithBreakLabelled() {
OUTERLOOP:
	for i := 0; i < rand.Int(); i++ {
		for j := 0; j < rand.Int(); j++ {
			b, e := ResourceCheck()
			if !b || e != nil {
				break OUTERLOOP
			}
			FooFunc(G{}) // Breaking out of enclosing loop is also fine
		}
		// Some paths don't satisfy the condition here
		FooFunc(G{}) // @InvalidCall(funcCond)
	}
}

func callFooCheckInLoopWithContinueAndBreakWrongCheck() {
	for i := 0; i < rand.Int(); i++ {
		b, e := ResourceCheck()
		if !b {
			break
		}
		if e == nil { // wrong check
			continue
		}
		FooFunc(G{}) // @InvalidCall(funcCond)
	}
}

func callFooCheckInLoopWithCrazyGoto() {
	for i := 0; i < rand.Int(); i++ {
		b, e := ResourceCheck()
		if !b {
			break
		}
		if e == nil {
			goto FINISH
		}
	}
	return
FINISH:
	FooFunc(G{})
}

func callFooCheckInLoopWithCrazyGotoWrongCheck() {
	for i := 0; i < rand.Int(); i++ {
		b, e := ResourceCheck()
		if b {
			break
		}
		if e == nil {
			goto FINISH
		}
	}
	return
FINISH:
	FooFunc(G{}) // @InvalidCall(funcCond)
}

func callFooInSelect(input1, input2 chan int, done chan bool, timeout time.Duration) {
	timer := time.NewTimer(timeout)

	for {
		select {
		case val1 := <-input1:
			fmt.Printf("Received from input1: %d\n", val1)

		case val2 := <-input2:
			fmt.Printf("Received from input2:%d\n", val2)
			// check and call
			if FooPreCheck() {
				FooFunc(G{})
			}

		case <-done:
			fmt.Println("Received done signal, exiting")
			// call unchecked
			FooFunc(G{}) // @InvalidCall(funcCond)
			return

		case <-timer.C:
			fmt.Println("Timeout reached")
			return

		default:
			// This case is optional - it will execute when no other cases are ready
			fmt.Println("No data available, waiting...")
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func main() {
	callFooChecked()
	callFooUnChecked()
	callFooWrongChecked()
	callFooCheckedPathNoReturns()
	callFooResourceCheck()
	callFooCheckedWithInterface(G{})
	callFooResourceCheckTwoConds()
	callFooResourceCheckTwoCondsSwap()
	callFooCheckInLoopWithBreak()
	callFooCheckInLoopWithBreakLabelled()
	callFooCheckInLoopWithContinue()
	callFooCheckInLoopWithContinueAndBreakWrongCheck()
	callFooResourceCheckTwoCondsRev()
	callFooCheckInLoopWithCrazyGoto()
	callFooCheckInLoopWithCrazyGotoWrongCheck()
	callFooResourceCheckTwoCondsWrong()
	callFooDoubleChecked()
	callFooCheckInLoop()
	callFooWrongCheckInLoop()

	input1 := make(chan int)
	input2 := make(chan int)
	done := make(chan bool)

	// Start the processing
	go callFooInSelect(input1, input2, done, 5*time.Second)

	// Send some data
	go func() {
		input1 <- 1
		input2 <- 2
		time.Sleep(time.Second)
		done <- true
	}()

	// Wait to see the results
	time.Sleep(6 * time.Second)
}
