package main

func main() {
	go func() {
		panic("whatnot")
	}()
}
