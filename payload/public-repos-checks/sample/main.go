package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

var privateKeyPath string

func init() {
	flag.StringVar(&privateKeyPath, "key", "", "Path to ECDSA private key file")
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

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter commands (greet, calc, time, sign, quit):")

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
		case "quit":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Unknown command. Try: greet, calc, time, sign, quit")
		}
	}
}
