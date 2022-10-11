package staticcommands_test

import (
	"os"
	"path/filepath"
	"testing"

	staticcommands "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/static-commands"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAll(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get wd: %s", err)
	}

	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	analysistest.Run(t, testdata, staticcommands.Analyzer, "static-commands")
}
