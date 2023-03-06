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
