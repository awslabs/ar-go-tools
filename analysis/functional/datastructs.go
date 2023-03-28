package functional

type Tree[T any] struct {
	Parent   *Tree[T]
	Children []*Tree[T]
	Label    T
}

func NewTree[T any](rootLabel T) *Tree[T] {
	return &Tree[T]{
		Parent:   nil,
		Children: nil,
		Label:    rootLabel,
	}
}

// Label returns the label of its argument
func Label[T any](t *Tree[T]) T {
	return t.Label
}

func (t *Tree[T]) AddChild(label T) *Tree[T] {
	newChild := &Tree[T]{
		Parent:   t,
		Children: nil,
		Label:    label,
	}
	if t.Children == nil {
		t.Children = []*Tree[T]{newChild}
	} else {
		t.Children = append(t.Children, newChild)
	}
	return newChild
}

// Ancestors returns the chain of the n closest ancestors of t. If n < 0, then it returns the chain up to the root
// of the tree
func (t *Tree[T]) Ancestors(n int) []*Tree[T] {
	var ans []*Tree[T]
	cur := t
	i := 0
	for cur != nil && (i < n || n < 0) {
		ans = append(ans, cur)
		cur = cur.Parent
		i += 1
	}
	Reverse(ans)
	return ans
}
