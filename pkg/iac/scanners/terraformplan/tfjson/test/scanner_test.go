package json

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/tfjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

func Test_Scanning_Plan(t *testing.T) {
	scanner := tfjson.New(
		options.ScannerWithEmbeddedPolicies(true),
		options.ScannerWithEmbeddedLibraries(true),
	)
	b, _ := os.ReadFile("testdata/plan.json")
	testFS := fstest.MapFS{
		"testdata/plan.json": {Data: b},
	}

	results, err := scanner.ScanFile("testdata/plan.json", testFS)
	require.NoError(t, err)
	require.NotNil(t, results)

	var failedResults scan.Results
	for _, r := range results {
		if r.Status() == scan.StatusFailed {
			failedResults = append(failedResults, r)
		}
	}
	assert.Len(t, results, 15)
	assert.Len(t, failedResults, 9)

}
