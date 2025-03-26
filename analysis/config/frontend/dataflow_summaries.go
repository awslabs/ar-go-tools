package frontend

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Summaries represents a set of summaries
type Summaries struct {
	// DataflowSummaries
	DataflowSummaries []DataflowSummary `json:"dataflow-summaries" yaml:"dataflow-summaries"`
}

// DataflowSummary is a single dataflow summary, either for an interface method or for a function
type DataflowSummary struct {
	Package   string        `json:"package" yaml:"package"`
	Interface string        `json:"interface" yaml:"interface"`
	Function  string        `json:"function" yaml:"function"`
	Method    string        `json:"method" yaml:"method"`
	Flows     []FlowSummary `json:"flows" yaml:"flows"`
}

// FlowSummary is a data flow from an origin to a destination
type FlowSummary struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`
}

// ParseSummariesFile parses a file that represents a Summaries structure. The structure can be
// serialized either in yaml or json format.
func ParseSummariesFile(path string) (*Summaries, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var summaries *Summaries
	errJson := json.Unmarshal(content, &summaries)
	if errJson == nil {
		return summaries, nil
	}
	// try yaml
	errYaml := yaml.Unmarshal(content, &summaries)
	if errYaml != nil {
		return nil, errors.Join(errJson, errYaml)
	}
	return summaries, nil
}
