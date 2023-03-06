package main

import (
	"context"
	"fmt"
	"time"
)

func sink(v any) {
	fmt.Println(v)
}

func main() {
	msg := InstanceMessage{
		CreatedDate: time.Now().String(),
		Destination: "",
		MessageId:   "",
		Payload:     "",
		Topic:       "",
	}

	docState, _ := ParseSendCommandMessage(context.Background(), msg, "tmp", "mds")
	sink(docState)
}
