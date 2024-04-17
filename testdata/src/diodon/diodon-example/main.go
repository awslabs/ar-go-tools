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

// Package main implements a simple server using a verified MAC protocol.
// This is referenced as an example in the Diodon paper.
package main

import (
	"fmt"
	"os"
	"time"

	. "diodon-example/core"
)

func main() {
	secret := loadFromSecretStore()
	fmt.Printf("%v\n", secret) // ok, not tainted yet
	c := NewChannel(secret)
	fmt.Printf("%v\n", secret) // @Sink(secret)
	msg := message()           // @Source(msg)
	go func() {
		time.Sleep(1 * time.Second)
		msg = []byte("bye world")
	}()
	c.Safe = append(c.Safe, 0x0) // @Mod(channel)
	invalidate(&c.Safe)
	Send(c, msg /*@ ,1 @*/)  // @Source(channel) // @Escape(msg) // @ModSource(channel)
	fmt.Printf("%v", c)      // @Sink(secret, secret2)
	fmt.Printf("%v", c.Safe) // @Escape(secret, secret2)
}

func invalidate(b *[]byte) {
	(*b)[0] = 0x0 // @Mod(channel)
}

func message() []byte {
	return []byte("hello world")
}

func loadFromSecretStore() []byte {
	b, err := os.ReadFile("secrets")
	if err != nil {
		panic(err)
	}
	return b
}
