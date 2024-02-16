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
	"diodon-agent/crypto"
	"fmt"
)

type IDataChannel interface {
	PerformHandshake()
	LogReaderId() string
}

type DataChannel struct {
	kms         *crypto.KMS
	logLTPk     *rsa.PublicKey
	logReaderId string
	secrets     agentSecrets
}

func NewDataChannel(logReaderId string) (IDataChannel, error) {
	dc := &DataChannel{}
	if err := dc.initialize(logReaderId); err != nil {
		return nil, fmt.Errorf("failed to initialize data channel: %v", err)
	}

	return dc, nil
}

type agentSecrets struct {
	agentLTKeyARN string
}

func (dc *DataChannel) initialize(logReaderId string) error {
	kms, err := crypto.NewKMS()
	if err != nil {
		return fmt.Errorf("failed to initialize KMS")
	}
	dc.kms = kms
	agentLTKeyARN, logLTPk, err := getInitialValues(kms)
	dc.secrets.agentLTKeyARN = agentLTKeyARN // @Source(s1)
	dc.logLTPk = logLTPk
	dc.logReaderId = logReaderId
	return nil
}

func (dc *DataChannel) PerformHandshake() {
	dc.kms.Sign([]byte(sanitizeStr(dc.secrets.agentLTKeyARN)), []byte(sanitizeStr("message"))) // @Source(s2)
	// unexpected I/O operation on secret caught by the taint analysis
	fmt.Println(dc.secrets.agentLTKeyARN) // @Source(s3) @Sink(s1, s2, s3)
}

func (dc *DataChannel) LogReaderId() string {
	return dc.logReaderId
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

func sanitizeStr(s string) string {
	return s
}
