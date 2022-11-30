package main

import (
	"fmt"
	random "math/rand"
	"strconv"
)

func genString() string {
	n := random.Int() % 10
	s := ""
	for i := 0; i < n; i++ {
		s += fmt.Sprintf("-%d", i)
	}
	return s
}

func test4() {
	s1 := genString()
	sink1(s1)
	s1 = source3()
	sink1(s1) // this sink is reached by a tainted data
	var s []string
	for _, c := range s1 {
		s = append(s, strconv.Itoa(int(c)))
	}
	sink2(s[0]) // this sink is also reached
}
