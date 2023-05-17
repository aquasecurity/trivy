package integration

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/stretchr/testify/assert"
)

func Test_ExecuteK8sClusterScanVulns(t *testing.T) {
	actual := new(bytes.Buffer)
	commands.SetOut(actual)
	globalFlags := flag.NewGlobalFlagGroup()
	rootCmd := commands.NewRootCommand("k8s-test", globalFlags)
	k8s := commands.NewKubernetesCommand(globalFlags)
	rootCmd.AddCommand(k8s)
	rootCmd.SetArgs([]string{
		"k8s",
		"cluster",
		"--report",
		"summary",
		"-q",
		"--timeout",
		"5m0s",
		"--format",
		"json",
	})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	var rpt report.ConsolidatedReport
	var hasVulnerabilitiesFinding bool
	var hasMisconfigurationFinding bool
	err = json.Unmarshal([]byte(actual.String()), &rpt)
	assert.NoError(t, err)
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
