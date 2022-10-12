package bar

type Stuff struct {
	Pickles string
}

func MkStuff() Stuff {
	return Stuff{
		Pickles: "...",
	}
}
