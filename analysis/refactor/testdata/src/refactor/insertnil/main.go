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

func main() {
	x := "ok"
	y := []string{x}
	test1(x)
	z, _ := test4(x, &y[0])
	test2(z, y)
	_, _ = testInt(x, z)
	_, _ = testAnonStruct(&x, z)
}

func test1(x any /* @nonnil */) {
	if x != nil {
		print(x)
	}
}

func test2(x string, y []string /* @nonnil */) {
	print(x)
	for _, yy := range y {
		test3(&x, &yy)
	}
}

func test3(x, y *string /* @nonnil */) error {
	print(x)
	print(y)
	return nil
}

func test4(x string /* @nonnil */, y *string) (string, error) {
	print(x)
	print(y)
	return x + *y, nil
}

func testInt(a string /* @nonnil */, y string) (int, error) {
	print(a)
	print(y)
	return len(a + y), nil
}

func testAnonStruct(a *string /* @nonnil */, y string) (struct {
	y int
	x float32
}, error) {
	print(a)
	print(y)
	return struct {
		y int
		x float32
	}{
		y: len(*a), x: 0.1 * float32(len(*a)),
	}, nil
}
