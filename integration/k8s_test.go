//go:build k8s_integration

package integration

import (
	"encoding/json"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

// Note: the test required k8s (kind) cluster installed

func Test_ExecuteK8sClusterScanVulns(t *testing.T) {
	osArgs := []string{
		"k8s",
		"cluster",
		"--report",
		"summary",
		"-q",
		"--timeout",
		"5m0s",
		"--format",
		"json",
		"--components",
		"workload",
		"--context",
		"kind-kind-test",
	}
	// Set up the output file
	outputFile := filepath.Join(t.TempDir(), "output.json")
	osArgs = append(osArgs, []string{
		"--output",
		outputFile,
	}...)

	// Run Trivy
	err := execute(osArgs)
	assert.NoError(t, err)
	var rpt report.ConsolidatedReport
	actual, err := os.ReadFile(outputFile)
	err = json.Unmarshal([]byte(actual), &rpt)
	assert.NoError(t, err)
	var hasVulnerabilitiesFinding bool
	var hasMisconfigurationFinding bool
out:
	for _, res := range rpt.Findings {
		for _, res := range res.Results {
			if !hasMisconfigurationFinding && len(res.Misconfigurations) > 0 {
				hasMisconfigurationFinding = true
			}
			if !hasVulnerabilitiesFinding && len(res.Vulnerabilities) > 0 {
				hasVulnerabilitiesFinding = true
			}
			if hasMisconfigurationFinding && hasVulnerabilitiesFinding {
				break out
			}
		}
	}
	assert.True(t, hasMisconfigurationFinding)
	assert.True(t, hasVulnerabilitiesFinding)
}
