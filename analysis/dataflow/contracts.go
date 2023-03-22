package dataflow

import (
	"encoding/json"
	"io"
	"os"

	"github.com/awslabs/argot/analysis/summaries"
)

// A Contract for an interface specifies an interface id (the long name of the interface, i.e. package name followed
// by the type name) and a map from method names to dataflow summaries.
type Contract struct {
	InterfaceId string
	Methods     map[string]summaries.Summary
}

// Key returns a string identifying the method in the given contract. This can be used to store method information
// consistently across different usages
func (c Contract) Key(method string) string {
	return c.InterfaceId + "." + method
}

// LoadDefinitions loads the dataflow definitions contained in the json file at filename
// returns an error if it could not read the file, or the file is not well formatted.
func LoadDefinitions(fileName string) ([]Contract, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var data []Contract
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
