package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func checkEqualOnNonEmptyFields(t *testing.T, cid1 CodeIdentifier, cid2 CodeIdentifier) {
	cid2c := CompileRegexes(cid2)
	if !cid1.equalOnNonEmptyFields(cid2c) {
		t.Errorf("%v should be equal modulo empty fields to %v", cid1, cid2)
	}
}

func checkNotEqualOnNonEmptyFields(t *testing.T, cid1 CodeIdentifier, cid2 CodeIdentifier) {
	cid2c := CompileRegexes(cid2)
	if cid1.equalOnNonEmptyFields(cid2c) {
		t.Errorf("%v should not be equal modulo empty fields to %v", cid1, cid2)
	}
}

func TestCodeIdentifier_equalOnNonEmptyFields_selfEquals(t *testing.T) {
	cid1 := CodeIdentifier{"a", "b", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid1)
}

func TestCodeIdentifier_equalOnNonEmptyFields_emptyMatchesAny(t *testing.T) {
	cid1 := CodeIdentifier{"a", "b", "c", "d", "e", nil}
	cid2 := CodeIdentifier{"de", "234jbn", "23kjb", "d", "234", nil}
	cidEmpty := CodeIdentifier{}
	checkEqualOnNonEmptyFields(t, cid1, cidEmpty)
	checkEqualOnNonEmptyFields(t, cid2, cidEmpty)
}

func TestCodeIdentifier_equalOnNonEmptyFields_oneDiff(t *testing.T) {
	cid1 := CodeIdentifier{"a", "b", "", "", "", nil}
	cid2 := CodeIdentifier{"a", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkNotEqualOnNonEmptyFields(t, cid2, cid1)
}

func TestCodeIdentifier_equalOnNonEmptyFields_regexes(t *testing.T) {
	cid1 := CodeIdentifier{"main", "b", "", "", "", nil}
	cid1bis := CodeIdentifier{"command-line-arguments", "b", "", "", "", nil}
	cid2 := CodeIdentifier{"(main)|(command-line-arguments)$", "", "", "", "", nil}
	checkEqualOnNonEmptyFields(t, cid1, cid2)
	checkEqualOnNonEmptyFields(t, cid1bis, cid2)
}

func mkConfig(sanitizers []CodeIdentifier, sinks []CodeIdentifier, sources []CodeIdentifier) Config {
	return Config{Sanitizers: sanitizers, Sinks: sinks, Sources: sources}
}

func testLoadOneFile(t *testing.T, filename string, expected Config) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get wd: %s", err)
	}
	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	configFileName := filepath.Join(filepath.Join(testdata, "config-examples"), filename)
	config, err := Load(configFileName)
	if err != nil {
		t.Errorf("Error loading %s: %v", configFileName, err)
	}
	c1, err1 := yaml.Marshal(config)
	c2, err2 := yaml.Marshal(expected)
	if err1 != nil {
		t.Errorf("Error marshalling %v", config)
	}
	if err2 != nil {
		t.Errorf("Error marshalling %v", expected)
	}
	if string(c1) != string(c2) {
		t.Errorf("Error in %s:\n%s is not\n%s\n", filename, c1, c2)
	}

}

func TestLoad(t *testing.T) {
	//
	testLoadOneFile(
		t,
		"config.yaml",
		mkConfig(
			[]CodeIdentifier{{"a", "b", "", "", "", nil}},
			[]CodeIdentifier{{"c", "d", "", "", "", nil}},
			[]CodeIdentifier{},
		),
	)
	//
	testLoadOneFile(t,
		"config2.yaml",
		mkConfig(
			[]CodeIdentifier{{"x", "a", "", "b", "", nil}},
			[]CodeIdentifier{{"y", "b", "", "", "", nil}},
			[]CodeIdentifier{{"p", "a", "", "", "", nil},
				{"p2", "a", "", "", "", nil}},
		),
	)
	//
	testLoadOneFile(t,
		"config3.yaml",
		Config{
			Sanitizers: []CodeIdentifier{{"pkg1", "Foo", "Obj", "", "", nil}},
			Sinks: []CodeIdentifier{{"y", "b", "", "", "", nil},
				{"x", "", "Obj1", "", "", nil}},
			Sources: []CodeIdentifier{
				{"some/package", "SuperMethod", "", "", "", nil},

				{"some/other/package", "", "", "OneField", "ThatStruct", nil},
			},
			PkgPrefix: "a",
		},
	)
	// Test configuration file for static-commands
	osExecCid := CodeIdentifier{"os/exec", "Command", "", "", "", nil}
	testLoadOneFile(t,
		"config-find-osexec.yaml",
		Config{StaticCommands: []CodeIdentifier{osExecCid}})
}
