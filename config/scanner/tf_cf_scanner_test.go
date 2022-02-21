package scanner

import (
	"context"
	"testing"

	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerraformScanning(t *testing.T) {

	scanner, err := New("testdata", nil, nil, nil, false)
	require.NoError(t, err)

	misconfigurations, err := scanner.ScanConfigs(context.Background(), []types.Config{
		{
			Type:     types.Terraform,
			FilePath: "testdata/main.tf",
		},
	},
	)
	require.NoError(t, err)

	assert.Len(t, misconfigurations, 1)
	assert.Len(t, misconfigurations[0].Failures, 3)
	assert.Len(t, misconfigurations[0].Successes, 0)

	expectedErrorCodes := []string{"AVD-AWS-0107", "AVD-AWS-0124", "AVD-AZU-0038"}
	actualErrorCodes := getActualCodes(misconfigurations[0].Failures)
	assert.EqualValues(t, expectedErrorCodes, actualErrorCodes)

	var expectedSuccessCodes []string
	actualSuccessCodes := getActualCodes(misconfigurations[0].Successes)
	assert.EqualValues(t, expectedSuccessCodes, actualSuccessCodes)
}

func TestCloudFormationScanning(t *testing.T) {

	scanner, err := New("testdata", nil, nil, nil, false)
	require.NoError(t, err)

	misconfigurations, err := scanner.ScanConfigs(context.Background(), []types.Config{
		{
			Type:     types.CloudFormation,
			FilePath: "testdata/cloudformation.yaml",
		},
	},
	)
	require.NoError(t, err)

	assert.Len(t, misconfigurations, 1)
	assert.Len(t, misconfigurations[0].Failures, 7)
	assert.Len(t, misconfigurations[0].Successes, 3)

	expectedErrorCodes := []string{"AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0088", "AVD-AWS-0089", "AVD-AWS-0090", "AVD-AWS-0093", "AVD-AWS-0132"}
	actualErrorCodes := getActualCodes(misconfigurations[0].Failures)
	assert.EqualValues(t, expectedErrorCodes, actualErrorCodes)

	expectedSuccessCodes := []string{"AVD-AWS-0091", "AVD-AWS-0092", "AVD-AWS-0094"}
	actualSuccessCodes := getActualCodes(misconfigurations[0].Successes)
	assert.EqualValues(t, expectedSuccessCodes, actualSuccessCodes)
}

func getActualCodes(results []types.MisconfResult) []string {
	var actualErrorCodes []string

	for _, failure := range results {
		actualErrorCodes = append(actualErrorCodes, failure.ID)
	}
	return actualErrorCodes
}
