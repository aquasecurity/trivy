package json

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
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

	var got []string
	for _, r := range results.GetFailed() {
		got = append(got, r.Rule().ID)
	}

	expected := []string{
		"AVD-AWS-0093",
		"AVD-AWS-0086",
		"AVD-AWS-0132",
		"AVD-AWS-0094",
		"AVD-AWS-0087",
		"AVD-AWS-0091",
		"AVD-AWS-0099",
		"AVD-AWS-0124",
	}
	assert.ElementsMatch(t, expected, got)
}
