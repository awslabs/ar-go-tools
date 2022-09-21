package dependencies

import (
	"fmt"
	"testing"
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
