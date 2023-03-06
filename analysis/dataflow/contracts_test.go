package dataflow

import (
	"path"
	"runtime"
	"testing"
)

func TestAll(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	file := path.Join(path.Dir(filename), "../../testdata/src/taint/interface-summaries/dataflows.json")
	_, err := LoadDefinitions(file)
	if err != nil {
		t.Fatalf(err.Error())
	}
}
