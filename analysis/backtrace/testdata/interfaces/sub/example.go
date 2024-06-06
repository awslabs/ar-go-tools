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

package sub

type PublicType struct {
	Data string
}

type privateType1 struct {
	PublicType
	id string
}

type privateType2 struct {
	PublicType
	name string
}

func NewPrivateType1(data string) *privateType1 {
	return &privateType1{
		PublicType: PublicType{Data: data},
		id:         "private",
	}
}

func NewPrivateType2(data string) *privateType2 {
	return &privateType2{
		PublicType: PublicType{Data: data},
		name:       "private",
	}
}

func (p *PublicType) CommonFunc() string {
	return p.Data
}
