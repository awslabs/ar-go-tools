package utils

import (
	"path/filepath"
	"testing"

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/config"
	"golang.org/x/tools/go/ssa"
)

// LoadTest loads the program in the directory dir, looking for a main.go and a config.yaml. If additional files
// are specified as extraFiles, the program will be loaded using those files too.
func LoadTest(t *testing.T, dir string, extraFiles []string) (*ssa.Program, *config.Config) {
	var err error
	// Load config; in command, should be set using some flag
	configFile := filepath.Join(dir, "config.yaml")
	config.SetGlobalConfig(configFile)
	files := []string{filepath.Join(dir, "./main.go")}
	for _, extraFile := range extraFiles {
		files = append(files, filepath.Join(dir, extraFile))
	}

	pkgs, err := analysis.LoadProgram(nil, "", ssa.BuilderMode(0), files)
	if err != nil {
		t.Fatalf("error loading packages.")
	}
	cfg, err := config.LoadGlobal()
	if err != nil {
		t.Fatalf("error loading global config.")
	}
	return pkgs, cfg
}
