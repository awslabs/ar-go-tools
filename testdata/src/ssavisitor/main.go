package main

import "fmt"

func Foo(x int) int {
	return x*x + 1
}

func Bar(x int) []int {
	// ssa block 0
	s := make([]int, x)
	// ssa block 3
	for i := 0; i < x; i++ {
		// ssa block 1
		s[i] = Foo(i)
		if s[i] > 9 {
			// ssa block 4
			continue
		} else {
			// ssa block 5
			// ssa block 8
			for j := 0; j < x; j++ {
				// ssa block 6
				s[i] += 1
			}
			// ssa block 7
			return s
		}
	}
	// ssa block 2
	return s
}

func main() {
	c := make(chan int, 3)
	c <- 1
	c <- 2
	c <- 3
	for x := range c {
		for _, x := range Bar(x) {
			fmt.Println(x)
		}
	}
}
