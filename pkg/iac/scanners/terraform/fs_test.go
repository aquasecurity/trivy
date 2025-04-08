package terraform

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func Test_OS_FS(t *testing.T) {
	s := New(
		rego.WithEmbeddedPolicies(true),
		rego.WithEmbeddedLibraries(true),
	)
	results, err := s.ScanFS(t.Context(), os.DirFS("testdata"), "fail")
	require.NoError(t, err)
	assert.NotEmpty(t, results.GetFailed())
}
