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

// Package datachannel implements a simplified SSM Agent datachannel.
package datachannel

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"diodon-agent/crypto"
)

type IDataChannel interface {
	PerformHandshake() error
	LogReaderId() *string
}

type DataChannel struct {
	kms               *crypto.KMS
	logLTPk           *rsa.PublicKey
	logReaderId       string
	streamDataHandler func([]byte) error
	secrets           agentSecrets
}

func NewDataChannel(logReaderId string) (IDataChannel, error) {
	dc := &DataChannel{}
	if err := dc.initialize(logReaderId); err != nil {
		return nil, fmt.Errorf("failed to initialize data channel: %v", err)
	}
	dc.streamDataHandler = func(streamData []byte) error {
		return dc.handleHandshakeResponse(streamData)
	}

	return dc, nil
}

type agentSecrets struct {
	agentSecret   []byte
	sharedSecret  []byte
	sessionID     []byte
	agentWriteKey []byte
	agentReadKey  []byte
	// agentLTKeyARN is the ARN for the KMS long-term-key used to sign and verify the handshake
	agentLTKeyARN string
}

func (dc *DataChannel) initialize(logReaderId string) error {
	kms, err := crypto.NewKMS()
	if err != nil {
		return fmt.Errorf("failed to initialize KMS")
	}
	dc.kms = kms
	agentLTKeyARN, logLTPk, err := getInitialValues(kms)
	if err != nil {
		return fmt.Errorf("failed to get initial values")
	}
	dc.secrets.agentLTKeyARN = agentLTKeyARN
	dc.logLTPk = logLTPk
	dc.logReaderId = logReaderId
	return nil
}

func (dc *DataChannel) PerformHandshake() error {
	if err := dc.kms.Sign([]byte(sanitizeStr(dc.secrets.agentLTKeyARN)), []byte(sanitizeStr("message"))); err != nil {
		return fmt.Errorf("failed to sign key: %v", err)
	}

	// simulate handling message from network
	if err := dc.streamDataHandler([]byte("message")); err != nil {
		return err
	}

	// unexpected I/O operation on secret caught by the taint analysis
	fmt.Println(dc.secrets.sharedSecret) // @Sink(secret)

	return nil
}

func (dc *DataChannel) SetSessionId(id []byte) {
	dc.secrets.sessionID = id
}

func (dc *DataChannel) handleHandshakeResponse(streamDataMessage []byte) error {
	clientShare := string(streamDataMessage)                                               // simulate parsing
	sharedSecret, err := unmarshalAndCheckClientShare(clientShare, dc.secrets.agentSecret) // @Source(sharedSecret)
	if err != nil {                                                                        //argot:ignore
		return errors.New("failed")
	}

	dc.secrets.sessionID = computeSHA384(sharedSecret) // @Source(sessionId)

	return nil
}

func (dc *DataChannel) LogReaderId() *string {
	return &dc.logReaderId
}

func getInitialValues(kms *crypto.KMS) (string, *rsa.PublicKey, error) {
	agentLtkARN, err := kms.CreateKey()
	if err != nil {
		return "", nil, err
	}

	sk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", nil, err
	}

	logLTPk := &sk.PublicKey
	return agentLtkARN, logLTPk, nil
}

func unmarshalAndCheckClientShare(clientShare string, agentSecret []byte) ([]byte, error) {
	return append([]byte(clientShare), agentSecret...), nil
}

func computeSHA384(secret []byte) []byte {
	return secret
}

func sanitizeStr(s string) string {
	return s
}
