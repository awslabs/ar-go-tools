package config

// A CodeIdentifier identifies a code element that is a source, sink, sanitizer, etc..
// A code identifier can be identified from its package, method, receiver, field
// or type, or any combination of those
// This is meant to replicate functionality in go-flow-levee and gokart, and can be
// extended as needed
type CodeIdentifier struct {
	Package  string
	Method   string
	Receiver string
	Field    string
	Type     string
}

// equalOnNonEmptyFields returns true if each of the receiver's fields are either equal to the corresponding
// argument's field, or the argument's field is empty
func (cid CodeIdentifier) equalOnNonEmptyFields(cidRef CodeIdentifier) bool {
	return ((cid.Package == cidRef.Package) || (cidRef.Package == "")) &&
		((cid.Method == cidRef.Method) || (cidRef.Method == "")) &&
		((cid.Receiver == cidRef.Receiver) || (cidRef.Receiver == "")) &&
		((cid.Field == cidRef.Field) || (cidRef.Field == "")) &&
		((cid.Type == cidRef.Type) || (cidRef.Type == ""))
}

// ExistsCid is true if there is some x in a such that f(x) is true.
// O(len(a))
// TODO: optimize?
// TODO: make this generic when we have generics
func ExistsCid(a []CodeIdentifier, f func(identifier CodeIdentifier) bool) bool {
	for _, x := range a {
		if f(x) {
			return true
		}
	}
	return false
}
