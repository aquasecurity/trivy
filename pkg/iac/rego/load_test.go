package rego

import (
	"bytes"
	"embed"
	"testing"
	"testing/fstest"

	trivy_policies "github.com/aquasecurity/trivy-policies"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed all:testdata/policies
var testEmbedFS embed.FS

//go:embed testdata/embedded
var embeddedPoliciesFS embed.FS

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

func Test_FallbackToEmbedded(t *testing.T) {
	scanner := NewScanner(
		types.SourceDockerfile,
		options.ScannerWithRegoErrorLimits(0),
	)
	fsys := fstest.MapFS{
		"policies/my-policy2.rego": &fstest.MapFile{
			Data: []byte(`# METADATA
# schemas:
# - input: schema["fooschema"]

package builtin.test

deny {
input.evil == "foo bar"
}`),
		},
		"schemas/fooschema.json": &fstest.MapFile{
			Data: []byte(`{
				"$schema": "http://json-schema.org/draft-07/schema#",
				"type": "object",
				"properties": {
					"foo": {
						"type": "string"
					}
				}
			}`),
		},
	}
	trivy_policies.EmbeddedPolicyFileSystem = embeddedPoliciesFS
	err := scanner.LoadPolicies(false, false, fsys, []string{"."}, nil)
	assert.NoError(t, err)
}
