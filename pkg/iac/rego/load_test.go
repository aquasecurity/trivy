package rego

import (
	"bytes"
	"embed"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed all:testdata/policies
var testEmbedFS embed.FS

func Test_RegoScanning_WithSomeInvalidPolicies(t *testing.T) {
	t.Run("allow no errors", func(t *testing.T) {
		var debugBuf bytes.Buffer
		scanner := NewScanner(types.SourceDockerfile)
		scanner.SetRegoErrorLimit(0)
		scanner.SetDebugWriter(&debugBuf)
		p, _ := LoadPoliciesFromDirs(testEmbedFS, ".")
		require.NotNil(t, p)

		scanner.policies = p
		err := scanner.compilePolicies(testEmbedFS, []string{"policies"})
		require.ErrorContains(t, err, `want (one of): ["Cmd" "EndLine" "Flags" "JSON" "Original" "Path" "Stage" "StartLine" "SubCmd" "Value"]`)
		assert.Contains(t, debugBuf.String(), "Error(s) occurred while loading policies")
	})

	t.Run("allow up to max 1 error", func(t *testing.T) {
		var debugBuf bytes.Buffer
		scanner := NewScanner(types.SourceDockerfile)
		scanner.SetRegoErrorLimit(1)
		scanner.SetDebugWriter(&debugBuf)

		p, _ := LoadPoliciesFromDirs(testEmbedFS, ".")
		scanner.policies = p

		err := scanner.compilePolicies(testEmbedFS, []string{"policies"})
		require.NoError(t, err)

		assert.Contains(t, debugBuf.String(), "Error occurred while parsing: testdata/policies/invalid.rego, testdata/policies/invalid.rego:7")
	})

}
