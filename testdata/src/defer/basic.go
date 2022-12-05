package main

func arbitrary() bool
func external(int) int

func f1() int {
	if arbitrary() {
		return 0
	}
	defer func() {}()
	return 1
}

func f2() int {
	i := 1
	defer func() { i = 3 }()
	i = 4
	return external(i)
}

func f3() int {
	i := 1
	defer func() { println(i) }()
	i = 4
	if arbitrary() {
		external(5)
	}
	return i
}

func f4() (err error) {
	defer func() {
		err = *new(error)
	}()
	return nil
}

func f5() (err error) {
	for i := 0; i < 10; i++ {
		defer func() {
			err = *new(error)
		}()
	}
	return nil
}

func f6() (err error) {
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	return nil
}
func f7() (err error) {
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	return nil
}
