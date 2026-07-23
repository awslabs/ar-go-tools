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
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

var privateKeyPath string
var s3Bucket string
var encryptionKey string

func init() {
	flag.StringVar(&privateKeyPath, "key", "", "Path to ECDSA private key file")
	flag.StringVar(&s3Bucket, "bucket", "", "S3 bucket name")
	flag.StringVar(&encryptionKey, "enckey", "", "32-byte hex encryption key for AES-256")
	flag.Parse()
}

func greet() {
	fmt.Println("Hello there!")
}

func calculate() {
	fmt.Println("Performing calculation: 2 + 2 =", 2+2)
}

func showTime() {
	fmt.Println("Current time:", time.Now().Format("2006-01-02 15:04:05"))
}

func test() {
	curve := elliptic.P521()

	println(curve)
}

// parseECDHKey validates a raw hex-encoded, compressed P-224 curve point. This exercises the
// curve's point-decompression path (crypto/elliptic.UnmarshalCompressed ->
// crypto/internal/fips140/nistec.P224Point.SetBytes ->
// crypto/internal/fips140/nistec/fiat.P224Element.Square, as part of the curve-equation check).
func parseECDHKey(scanner *bufio.Scanner) {
	fmt.Print("Enter hex-encoded compressed P-224 point: ")
	if !scanner.Scan() {
		return
	}
	pointHex := strings.TrimSpace(scanner.Text())

	pointBytes, err := hex.DecodeString(pointHex)
	if err != nil {
		fmt.Printf("Error decoding point: %v\n", err)
		return
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P224(), pointBytes)
	if x == nil {
		fmt.Println("Error parsing point: invalid encoding")
		return
	}

	fmt.Printf("Parsed point: x=%x y=%x\n", x, y)
}

// checkOnCurve validates raw, attacker-controlled x/y coordinates against the P-224 curve
// equation. This directly exercises crypto/elliptic.Curve.IsOnCurve ->
// crypto/elliptic.nistCurve.pointFromAffine -> crypto/internal/fips140/nistec.P224Point.SetBytes
// -> crypto/internal/fips140/nistec/fiat.P224Element.Square (used in the curve-equation check).
func checkOnCurve(scanner *bufio.Scanner) {
	fmt.Print("Enter hex-encoded x coordinate: ")
	if !scanner.Scan() {
		return
	}
	xHex := strings.TrimSpace(scanner.Text())

	fmt.Print("Enter hex-encoded y coordinate: ")
	if !scanner.Scan() {
		return
	}
	yHex := strings.TrimSpace(scanner.Text())

	xBytes, xErr := hex.DecodeString(xHex)
	yBytes, yErr := hex.DecodeString(yHex)
	if xErr != nil || yErr != nil {
		fmt.Println("Error decoding coordinates")
		return
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	onCurve := elliptic.P224().IsOnCurve(x, y)
	fmt.Printf("On curve: %v\n", onCurve)
}

func signData(scanner *bufio.Scanner) {
	if privateKeyPath == "" {
		fmt.Println("No private key specified. Use -key flag.")
		return
	}

	fmt.Print("Enter data to sign: ")
	if !scanner.Scan() {
		return
	}
	data := scanner.Text()

	privKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		fmt.Printf("Error loading key: %v\n", err)
		return
	}

	hash := sha256.Sum256([]byte(data))
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		fmt.Printf("Error signing: %v\n", err)
		return
	}

	fmt.Printf("Signature: %s\n", hex.EncodeToString(sig))
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func generateCompressed() {
	curve := elliptic.P256()

	// Generate a key pair
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	// Marshal the public key in compressed format
	compressed := elliptic.MarshalCompressed(curve, x, y)

	fmt.Printf("Private key: %x\n", priv)
	fmt.Printf("Compressed public key: %x\n", compressed)
}

func encryptAndUpload(scanner *bufio.Scanner) {
	if s3Bucket == "" {
		fmt.Println("No S3 bucket specified. Use -bucket flag.")
		return
	}
	if encryptionKey == "" {
		fmt.Println("No encryption key specified. Use -enckey flag.")
		return
	}

	fmt.Print("Enter file path to upload: ")
	if !scanner.Scan() {
		return
	}
	filePath := strings.TrimSpace(scanner.Text())

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	encrypted, err := encryptData(data, encryptionKey)
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		return
	}

	err = uploadToS3(encrypted, filePath+".enc")
	if err != nil {
		fmt.Printf("Error uploading: %v\n", err)
		return
	}

	fmt.Println("File encrypted and uploaded successfully")
}

func encryptData(data []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func uploadToS3(data []byte, key string) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	})
	if err != nil {
		return err
	}

	svc := s3.New(sess)
	_, err = svc.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(key),
		Body:   strings.NewReader(string(data)),
	})

	return err
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter commands (greet, calc, time, sign, upload, ecdhkey, oncurve, quit):")
	generateCompressed()
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(strings.ToLower(scanner.Text()))

		switch input {
		case "greet":
			greet()
		case "calc":
			calculate()
		case "time":
			showTime()
		case "sign":
			signData(scanner)
		case "upload":
			encryptAndUpload(scanner)
		case "ecdhkey":
			parseECDHKey(scanner)
		case "oncurve":
			checkOnCurve(scanner)
		case "quit":
			fmt.Println("Goodbye!")
			return
		default:
			test()
			fmt.Println("Unknown command. Try: greet, calc, time, sign, upload, ecdhkey, oncurve, quit")
		}
	}
}
