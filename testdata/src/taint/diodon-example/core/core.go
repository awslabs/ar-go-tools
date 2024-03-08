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

// Package core implements a verified MAC communication protocol.
package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"os"
)

// Chan represents a channel containing a secret.
type Chan struct {
	psk  []byte
	Safe []byte
}

// NewChannel initializes a new channel with secret.
// @ ens Inv(c)
func NewChannel(secret []byte) (c *Chan) {
	c = &Chan{psk: secret, Safe: make([]byte, 1)} // @Source(secret) // @Mod(channel)
	return c
}

// Send sends message msg to the network via channel c.
// @ req Inv(c) && acc(msg, x) && 0 < x
// @ ens Inv(c) && acc(msg, x)
func Send(c *Chan, msg []byte /*@,x perm@*/) {
	packet := append(msg, HMAC(msg, c.psk)...) // @Source(secret2) @Escape(secret2)
	sendToNetwork(packet)
}

/*@ pred Inv(c *Chan) {
  c != nil && acc(c, 1) &&
  acc(c.psk, 1) && len(c.psk) == 16 &&
  AliceIOPermissions()
} @*/

// sendToNetwork sends packet to the network via TCP.
func sendToNetwork(packet []byte) {
	conn, err := net.DialTCP("network", nil, nil)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// unintentional leak of secret data: caught by taint analysis
	if err := os.WriteFile("/tmp/secrets", packet, os.ModeAppend); err != nil { // @Sink(secret, secret2, msg)
		panic(err)
	}

	// intentional leak of secret data specified in the Tamarin model
	// test nesting function calls
	f(conn, san(packet))
}

func f(conn *net.TCPConn, packet []byte) {
	leakSecret(conn, packet)
}

// HMAC returns the HMAC hash of msg using key.
func HMAC(msg, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	return mac.Sum(msg)
}

func leakSecret(conn *net.TCPConn, packet []byte) {
	if _, err := conn.Write(packet); err != nil {
		panic(err)
	}
}

// san sanitizes b.
// Used for allowlisting calls for the taint analysis.
func san(b []byte) []byte {
	return b
}
