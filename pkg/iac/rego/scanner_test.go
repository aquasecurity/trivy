package rego_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_RegoScanning_Deny(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `
# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
		FS: srcFS,
	})
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
}

func Test_RegoScanning_AbsolutePolicyPath_Deny(t *testing.T) {

	tmp := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(tmp, "policies"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "policies", "test.rego"), []byte(`# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing
package defsec.test

deny {
    input.evil
}`), 0o600))

	srcFS := os.DirFS(tmp)

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
		FS: srcFS,
	})
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
}

func Test_RegoScanning_Allow(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": false,
		},
	})
	require.NoError(t, err)

	assert.Empty(t, results.GetFailed())
	require.Len(t, results.GetPassed(), 1)
	assert.Empty(t, results.GetIgnored())

	assert.Equal(t, "/evil.lol", results.GetPassed()[0].Metadata().Range().GetFilename())
}

func Test_RegoScanning_WithRuntimeValues(t *testing.T) {

	t.Setenv("DEFSEC_RUNTIME_VAL", "AOK")

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

deny_evil {
    output := opa.runtime()
	output.env.DEFSEC_RUNTIME_VAL == "AOK"
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())
}

func Test_RegoScanning_WithDenyMessage(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

deny[msg] {
    input.evil
	msg := "oh no"
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
}

func Test_RegoScanning_WithDenyMetadata_ImpliedPath(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `
# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

deny[res] {
    input.evil
	res := {
		"msg": "oh no",
		"startline": 123,
		"endline": 456,
	}
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.Equal(t, 123, results.GetFailed()[0].Metadata().Range().GetStartLine())
	assert.Equal(t, 456, results.GetFailed()[0].Metadata().Range().GetEndLine())

}

func Test_RegoScanning_WithDenyMetadata_PersistedPath(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `
# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

deny[res] {
    input.evil
	res := {
		"msg": "oh no",
		"startline": 123,
		"endline": 456,
		"filepath": "/blah.txt",
	}
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/blah.txt", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.Equal(t, 123, results.GetFailed()[0].Metadata().Range().GetStartLine())
	assert.Equal(t, 456, results.GetFailed()[0].Metadata().Range().GetEndLine())

}

func Test_RegoScanning_WithStaticMetadata(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `
package defsec.test

__rego_metadata__ := {
	"id": "AA001",
	"avd_id": "AVD-XX-9999",
	"title": "This is a title",
	"short_code": "short-code",
	"severity": "LOW",
	"type": "Dockerfile Security Check",
	"description": "This is a description",
	"recommended_actions": "This is a recommendation",
	"url": "https://google.com",
}

deny[res] {
    input.evil
	res := {
		"msg": "oh no",
		"startline": 123,
		"endline": 456,
		"filepath": "/blah.txt",
	}
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	failure := results.GetFailed()[0]

	assert.Equal(t, "oh no", failure.Description())
	assert.Equal(t, "/blah.txt", failure.Metadata().Range().GetFilename())
	assert.Equal(t, 123, failure.Metadata().Range().GetStartLine())
	assert.Equal(t, 456, failure.Metadata().Range().GetEndLine())
	assert.Equal(t, "AVD-XX-9999", failure.Rule().AVDID)
	assert.True(t, failure.Rule().HasID("AA001"))
	assert.Equal(t, "This is a title", failure.Rule().Summary)
	assert.Equal(t, severity.Low, failure.Rule().Severity)
	assert.Equal(t, "This is a recommendation", failure.Rule().Resolution)
	assert.Equal(t, "https://google.com", failure.Rule().Links[0])

}

func Test_RegoScanning_WithMatchingInputSelector(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

__rego_input__ := {
	"selector": [{"type": "json"}],
}

deny {
    input.evil
}

`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())
}

func Test_RegoScanning_WithNonMatchingInputSelector(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `
package defsec.test

__rego_input__ := {
	"selector": [{"type": "testing"}],
}

deny {
    input.evil
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Empty(t, results.GetFailed())
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())
}

func Test_RegoScanning_NoTracingByDefault(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	assert.Empty(t, results.GetFailed()[0].Traces())
}

func Test_RegoScanning_GlobalTracingEnabled(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test

deny {
    input.evil
}
`,
	})

	traceBuffer := bytes.NewBuffer([]byte{})

	scanner := rego.NewScanner(
		rego.WithTrace(traceBuffer),
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	assert.Empty(t, results.GetFailed()[0].Traces())
	assert.NotEmpty(t, traceBuffer.Bytes())
}

func Test_RegoScanning_PerResultTracingEnabled(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPerResultTracing(true),
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())

	assert.NotEmpty(t, results.GetFailed()[0].Traces())
}

func Test_dynamicMetadata(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `
package defsec.test

__rego_metadata__ := {
  "title" : sprintf("i am %s",[input.text])
}

deny {
  input.text
}

`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"text": "dynamic",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "i am dynamic", results[0].Rule().Summary)
}

func Test_staticMetadata(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `
package defsec.test

__rego_metadata__ := {
  "title" : "i am static"
}

deny {
  input.text
}

`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"text": "test",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "i am static", results[0].Rule().Summary)
}

func Test_annotationMetadata(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: i am a title
# description: i am a description
# related_resources:
# - https://google.com
# custom:
#   id: EG123
#   avd_id: AVD-EG-0123
#   severity: LOW
#   recommended_action: have a cup of tea
package defsec.test

deny {
  input.text
}

`,
		"policies/test2.rego": `# METADATA
# title: i am another title
package defsec.test2

deny {
  input.blah
}

`,
	})

	scanner := rego.NewScanner(
		rego.WithPerResultTracing(true),
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"text": "test",
		},
	})
	require.NoError(t, err)
	require.Len(t, results.GetFailed(), 1)
	failure := results.GetFailed()[0].Rule()
	assert.Equal(t, "i am a title", failure.Summary)
	assert.Equal(t, "i am a description", failure.Explanation)
	require.Len(t, failure.Links, 1)
	assert.Equal(t, "https://google.com", failure.Links[0])
	assert.Equal(t, "AVD-EG-0123", failure.AVDID)
	assert.Equal(t, severity.Low, failure.Severity)
	assert.Equal(t, "have a cup of tea", failure.Resolution)
}

func Test_RegoScanning_WithInvalidInputSchema(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# schemas:
# - input: schema["input"]
package defsec.test

deny {
    input.evil == "lol"
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))
}

func Test_RegoScanning_WithValidInputSchema(t *testing.T) {

	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# schemas:
# - input: schema["input"]
package defsec.test

deny {
    input.Stages[0].Commands[0].Cmd == "lol"
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))
}

func Test_RegoScanning_WithFilepathToSchema(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# schemas:
# - input: schema["dockerfile"]
package defsec.test

deny {
    input.evil == "lol"
}
`,
	})

	scanner := rego.NewScanner(
		rego.WithRegoErrorLimits(0),
		rego.WithPolicyDirs("policies"),
	)

	assert.ErrorContains(
		t,
		scanner.LoadPolicies(srcFS),
		"undefined ref: input.evil",
	)
}

func Test_RegoScanning_CustomData(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test
import data.settings.DS123.foo_bar_baz

deny {
    not foo_bar_baz
}
`,
	})

	dataFS := testutil.CreateFS(map[string]string{
		"data/data.json": `{
	"settings": {
		"DS123":{
			"foo_bar_baz":false
		}
	}
}`,
		"data/junk.txt": "this file should be ignored",
	})

	scanner := rego.NewScanner(
		rego.WithDataFilesystem(dataFS),
		rego.WithDataDirs("."),
		rego.WithPolicyDirs("policies"),
	)

	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{})
	require.NoError(t, err)

	assert.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())
}

func Test_RegoScanning_InvalidFS(t *testing.T) {
	srcFS := testutil.CreateFS(map[string]string{
		"policies/test.rego": `# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing

package defsec.test
import data.settings.DS123.foo_bar_baz

deny {
    not foo_bar_baz
}
`,
	})

	dataFS := testutil.CreateFS(map[string]string{
		"data/data.json": `{
	"settings": {
		"DS123":{
			"foo_bar_baz":false
		}
	}
}`,
		"data/junk.txt": "this file should be ignored",
	})

	scanner := rego.NewScanner(
		rego.WithDataFilesystem(dataFS),
		rego.WithDataDirs("X://"),
		rego.WithPolicyDirs("policies"),
	)

	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{})
	require.NoError(t, err)

	assert.Len(t, results.GetFailed(), 1)
	assert.Empty(t, results.GetPassed())
	assert.Empty(t, results.GetIgnored())
}

func Test_NoErrorsWhenUsingBadRegoCheck(t *testing.T) {

	// this check cause eval_conflict_error
	// https://www.openpolicyagent.org/docs/latest/policy-language/#functions
	fsys := fstest.MapFS{
		"checks/bad.rego": {
			Data: []byte(`package defsec.test

p(x) = y {
    y := x[_]
}

deny {
	p([1, 2, 3])
}
`),
		},
	}

	scanner := rego.NewScanner(
		rego.WithPolicyDirs("checks"),
	)
	require.NoError(t, scanner.LoadPolicies(fsys))
	_, err := scanner.ScanInput(t.Context(), types.SourceYAML, rego.Input{})
	require.NoError(t, err)
}

func Test_RegoScanning_WithDeprecatedCheck(t *testing.T) {

	check := `# METADATA
# title: i am a deprecated check
# description: i am a description
# related_resources:
# - https://google.com
# custom:
#   id: EG123
#   avd_id: AVD-EG-0123
#   severity: LOW
#   recommended_action: have a cup of tea
#   deprecated: %v
package defsec.test

deny {
  input.text
}`

	var testCases = []struct {
		name            string
		policy          string
		opts            []options.ScannerOption
		expectedResults int
	}{
		{
			name:            "deprecated check is skipped by default",
			policy:          fmt.Sprintf(check, true),
			expectedResults: 0,
		},
		{
			name:            "non-deprecated check is executed",
			policy:          fmt.Sprintf(check, false),
			expectedResults: 1,
		},
		{
			name:            "deprecated check is executed when includeDeprecatedChecks is true",
			policy:          fmt.Sprintf(check, true),
			opts:            []options.ScannerOption{rego.WithIncludeDeprecatedChecks(true)},
			expectedResults: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append(tc.opts, rego.WithPolicyReader(strings.NewReader(tc.policy)))
			scanner := rego.NewScanner(opts...)
			require.NoError(t, scanner.LoadPolicies(nil))

			results, err := scanner.ScanInput(t.Context(), types.SourceJSON, rego.Input{
				Path: "/evil.lol",
				Contents: map[string]any{
					"text": "test",
				},
			})
			require.NoError(t, err)
			require.Len(t, results, tc.expectedResults, tc.name)
		})
	}
}

func Test_RegoScanner_WithCustomSchemas(t *testing.T) {

	schema := `{
  "$id": "https://example.com/test.schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "service": { "type": "string" }
  },
  "required": ["service"]
}`

	tests := []struct {
		name            string
		check           string
		expectedResults int
	}{
		{
			name: "happy path",
			check: `# METADATA
# title: test check
# schemas:
# - input: schema["test"]
package user.test

deny {
	input.service == "test"
}
`,
			expectedResults: 1,
		},
		{
			name: "sad path",
			check: `# METADATA
# title: test check
# schemas:
# - input: schema["test"]
package user.test

deny {
	input.other == "test"
}
`,
			expectedResults: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scanner := rego.NewScanner(
				rego.WithCustomSchemas(map[string][]byte{
					"test": []byte(schema),
				}),
				rego.WithPolicyNamespaces("user"),
				rego.WithPolicyReader(strings.NewReader(tc.check)),
			)

			require.NoError(t, scanner.LoadPolicies(nil))

			results, err := scanner.ScanInput(t.Context(), types.SourceYAML, rego.Input{
				Path:     "test.yaml",
				Contents: map[string]any{"service": "test"},
			})
			require.NoError(t, err)
			require.Len(t, results, tc.expectedResults, tc.name)
		})
	}
}
