package terraform

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_OS_FS(t *testing.T) {
	s := New(
		options.ScannerWithDebug(os.Stderr),
		options.ScannerWithEmbeddedPolicies(true),
		options.ScannerWithEmbeddedLibraries(true),
	)
	results, err := s.ScanFS(context.TODO(), os.DirFS("testdata"), "fail")
	require.NoError(t, err)
	assert.Greater(t, len(results.GetFailed()), 0)
}
