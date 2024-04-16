package rego_test

import (
	"bytes"
	"embed"
	"io"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

//go:embed all:testdata/policies
var testEmbedFS embed.FS

func Test_RegoScanning_WithSomeInvalidPolicies(t *testing.T) {
	t.Run("allow no errors", func(t *testing.T) {
		var debugBuf bytes.Buffer
		scanner := rego.NewScanner(
			types.SourceDockerfile,
			options.ScannerWithRegoErrorLimits(0),
			options.ScannerWithDebug(&debugBuf),
		)

		err := scanner.LoadPolicies(false, false, testEmbedFS, []string{"."}, nil)
		require.ErrorContains(t, err, `want (one of): ["Cmd" "EndLine" "Flags" "JSON" "Original" "Path" "Stage" "StartLine" "SubCmd" "Value"]`)
		assert.Contains(t, debugBuf.String(), "Error(s) occurred while loading policies")
	})

	t.Run("allow up to max 1 error", func(t *testing.T) {
		var debugBuf bytes.Buffer
		scanner := rego.NewScanner(
			types.SourceDockerfile,
			options.ScannerWithRegoErrorLimits(1),
			options.ScannerWithDebug(&debugBuf),
		)

		err := scanner.LoadPolicies(false, false, testEmbedFS, []string{"."}, nil)
		require.NoError(t, err)

		assert.Contains(t, debugBuf.String(), "Error occurred while parsing: testdata/policies/invalid.rego, testdata/policies/invalid.rego:7")
	})

	t.Run("schema does not exist", func(t *testing.T) {
		check := `# METADATA
# schemas:
# - input: schema["fooschema"]
package mypackage

deny {
    input.evil == "foo bar"
}`
		scanner := rego.NewScanner(types.SourceJSON)

		err := scanner.LoadPolicies(false, false, fstest.MapFS{}, []string{"."}, []io.Reader{strings.NewReader(check)})
		assert.ErrorContains(t, err, "could not find schema \"fooschema\"")
	})

	t.Run("schema is invalid", func(t *testing.T) {
		check := `# METADATA
# schemas:
# - input: schema["fooschema"]
package mypackage

deny {
    input.evil == "foo bar"
}`
		scanner := rego.NewScanner(types.SourceJSON)

		fsys := fstest.MapFS{
			"schemas/fooschema.json": &fstest.MapFile{
				Data: []byte("bad json"),
			},
		}

		err := scanner.LoadPolicies(false, false, fsys, []string{"."}, []io.Reader{strings.NewReader(check)})
		assert.ErrorContains(t, err, "could not parse schema \"fooschema\"")
	})

	t.Run("schema is not specified", func(t *testing.T) {
		check := `package mypackage

deny {
    input.evil == "foo bar"
}`
		scanner := rego.NewScanner(types.SourceJSON)
		err := scanner.LoadPolicies(false, false, fstest.MapFS{}, []string{"."}, []io.Reader{strings.NewReader(check)})
		assert.NoError(t, err)
	})

}
