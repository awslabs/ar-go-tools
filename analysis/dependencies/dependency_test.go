package dependencies

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"golang.org/x/tools/go/ssa"
)

func TestComputePath(t *testing.T) {
	x := computePath("/Users/kienzld/gozer/src/ARG-GoAnalyzer/amazon-ssm-agent/agent/managedInstances/registration/instance_info.go",
		"github.com/aws/amazon-ssm-agent/agent/managedInstances/registration")
	if x != "github.com/aws/amazon-ssm-agent/agent/managedInstances/registration/instance_info.go" {
		t.Errorf("error")
	}
	fmt.Println(x)
}

// if the full package name does not appear, we have a situation where the
// filepath doesn't contain the full repo.  This is common when the go.mod contains
// the actual root of the project e.g.
//   filepath = /Users/kienzld/gozer/src/ARG-GoAnalyzer/amazon-ssm-agent/agent/managedInstances/registration/instance_info.go
//   pkg = github.com/aws/amazon-ssm-agent/agent/managedInstances/registration
// we need to iterate through progressively removing the initial elements from the package name
// until we find a match.

func TestComputePath2(t *testing.T) {
	x := computePath("/Users/kienzld/reference/Amazon-ssm-agent/agent/agent/agent.go",
		"github.com/aws/amazon-ssm-agent/agent/agent")
	if x != "github.com/aws/amazon-ssm-agent/agent/agent/agent.go" {
		t.Errorf("error")
	}
	fmt.Println(x)
}

//computePath(
///Users/kienzld/reference/Amazon-ssm-agent/agent/agent/agent.go
//github.com/aws/amazon-ssm-agent/agent/agent
//github.com/aws/amazon-ssm-agent/agent/agent/agent.go

func TestAgentWorkerDependencies(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../amazon-ssm-agent/")
	err := os.Chdir(dir)
	if err != nil {
		// We don't expect the agent to be in the pipeline, so don't fail here
		t.Logf("could not change to agent dir: %s", err)
		return
	}

	files := []string{"agent/agent.go", "agent/agent_parser.go", "agent/agent_unix.go"}
	program, err := analysis.LoadProgram(nil, "", ssa.BuilderMode(0), files)
	if err != nil {
		t.Fatalf("error loading packages: %s", err)
	}

	dependencyGraph := DependencyAnalysis(program, false, true, nil, false)

	if dependencyGraph != nil {
		//fmt.Println("Checking cycles in dependency graph")
		if dependencyGraph.Cycles() {
			t.Errorf("found cycles in the dependency graph")
		}
	}
}
