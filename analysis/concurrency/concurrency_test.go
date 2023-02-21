package concurrency

import (
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"testing"

	. "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/functional"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/utils"
)

func loadConcurrencyTestResult(t *testing.T, subDir string) AnalysisResult {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/concurrency/", subDir)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	program, cfg := utils.LoadTest(t, ".", []string{})
	ar, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}
	// Remove reports - comment if you want to inspect
	os.RemoveAll(cfg.ReportsDir)
	return ar
}

func TestTrivial(t *testing.T) {
	ar := loadConcurrencyTestResult(t, "trivial")

	for goInstr, id := range ar.GoCalls {
		t.Logf("%d : %s @ %s", id, goInstr, ar.Cache.Program.Fset.Position(goInstr.Pos()))
	}

	res := make([]string, len(ar.NodeColors))
	for node, color := range ar.NodeColors {

		e := strings.Join(Map(SetToSlice(color), func(i uint32) string { return strconv.Itoa(int(i)) }), ",")
		t.Logf("Node %s - %s", node.String(), e)
		if node.ID == 1 || // f1
			node.ID == 2 || // g2
			node.ID == 3 || // g
			node.ID == 9 || // g3
			node.ID == 0 || // root
			node.ID == 11 { // init
			if len(color) > 1 {
				t.Logf("Error: expected %s to be only in main routine", node)
			}
		}
		if node.ID == 7 && len(color) != 2 { // g1
			t.Logf("Error: expected g1() to be in its own routine and no other")
		}
		res[node.ID] = e
	}
	if res[5] != res[10] { // f4 and f5
		t.Logf("Expected f4 and f5 to have same identity")
	}
	if res[4] != res[6] { // f4 and f5
		t.Logf("Expected f2 and f3 to have same identity")
	}
}
