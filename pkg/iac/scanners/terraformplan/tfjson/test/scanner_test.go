package json

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/tfjson"
)

func Test_Scanning_Plan(t *testing.T) {
	scanner := tfjson.New(
		rego.WithEmbeddedPolicies(true),
		rego.WithEmbeddedLibraries(true),
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

	assert.Len(t, failedResults, 8)

}
