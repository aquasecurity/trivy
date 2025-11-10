package test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation"
)

func Test_basic_cloudformation_scanning(t *testing.T) {
	cfScanner := cloudformation.New(rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true))

	results, err := cfScanner.ScanFS(t.Context(), os.DirFS("./examples/bucket"), ".")
	require.NoError(t, err)

	assert.NotEmpty(t, results.GetFailed())
}

func Test_cloudformation_scanning_has_expected_errors(t *testing.T) {
	cfScanner := cloudformation.New(rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true))

	results, err := cfScanner.ScanFS(t.Context(), os.DirFS("./examples/bucket"), ".")
	require.NoError(t, err)

	assert.NotEmpty(t, results.GetFailed())
}
