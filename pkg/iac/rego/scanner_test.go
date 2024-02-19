package rego

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/liamg/memoryfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

func CreateFS(t *testing.T, files map[string]string) fs.FS {
	memfs := memoryfs.New()
	for name, content := range files {
		name := strings.TrimPrefix(name, "/")
		err := memfs.MkdirAll(filepath.Dir(name), 0o700)
		require.NoError(t, err)
		err = memfs.WriteFile(name, []byte(content), 0o644)
		require.NoError(t, err)
	}
	return memfs
}

func Test_RegoScanning_Deny(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		FS: srcFS,
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.False(t, results.GetFailed()[0].IsWarning())
}

func Test_RegoScanning_AbsolutePolicyPath_Deny(t *testing.T) {

	tmp := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(tmp, "policies"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "policies", "test.rego"), []byte(`package defsec.test

deny {
    input.evil
}`), 0600))

	srcFS := os.DirFS(tmp)

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"/policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		FS: srcFS,
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.False(t, results.GetFailed()[0].IsWarning())
}

func Test_RegoScanning_Warn(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

warn {
    input.evil
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	require.Equal(t, 0, len(results.GetPassed()))
	require.Equal(t, 0, len(results.GetIgnored()))

	assert.True(t, results.GetFailed()[0].IsWarning())
}

func Test_RegoScanning_Allow(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": false,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 0, len(results.GetFailed()))
	require.Equal(t, 1, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "/evil.lol", results.GetPassed()[0].Metadata().Range().GetFilename())
}

func Test_RegoScanning_Namespace_Exception(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
		"policies/exceptions.rego": `
package namespace.exceptions

import data.namespaces

exception[ns] {
    ns := data.namespaces[_]
    startswith(ns, "defsec")
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 0, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 1, len(results.GetIgnored()))

}

func Test_RegoScanning_Namespace_Exception_WithoutMatch(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`, "policies/something.rego": `
package builtin.test

deny_something {
    input.something
}
`,
		"policies/exceptions.rego": `
package namespace.exceptions

import data.namespaces

exception[ns] {
    ns := data.namespaces[_]
    startswith(ns, "builtin")
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 1, len(results.GetIgnored()))

}

func Test_RegoScanning_Rule_Exception(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test
deny_evil {
    input.evil
}
`,
		"policies/exceptions.rego": `
package defsec.test

exception[rules] {
    rules := ["evil"]
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 0, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 1, len(results.GetIgnored()))
}

func Test_RegoScanning_Rule_Exception_WithoutMatch(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test
deny_evil {
    input.evil
}
`,
		"policies/exceptions.rego": `
package defsec.test

exception[rules] {
    rules := ["good"]
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_WithRuntimeValues(t *testing.T) {

	_ = os.Setenv("DEFSEC_RUNTIME_VAL", "AOK")

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny_evil {
    output := opa.runtime()
	output.env.DEFSEC_RUNTIME_VAL == "AOK"
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_WithDenyMessage(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny[msg] {
    input.evil
	msg := "oh no"
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
}

func Test_RegoScanning_WithDenyMetadata_ImpliedPath(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
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

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.Equal(t, 123, results.GetFailed()[0].Metadata().Range().GetStartLine())
	assert.Equal(t, 456, results.GetFailed()[0].Metadata().Range().GetEndLine())

}

func Test_RegoScanning_WithDenyMetadata_PersistedPath(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
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

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/blah.txt", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.Equal(t, 123, results.GetFailed()[0].Metadata().Range().GetStartLine())
	assert.Equal(t, 456, results.GetFailed()[0].Metadata().Range().GetEndLine())

}

func Test_RegoScanning_WithStaticMetadata(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
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

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

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
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

__rego_input__ := {
	"selector": [{"type": "json"}],
}

deny {
    input.evil
}

`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_WithNonMatchingInputSelector(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
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

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 0, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_NoTracingByDefault(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Len(t, results.GetFailed()[0].Traces(), 0)
}

func Test_RegoScanning_GlobalTracingEnabled(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	traceBuffer := bytes.NewBuffer([]byte{})

	scanner := NewScanner(types.SourceJSON, options.ScannerWithTrace(traceBuffer))
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Len(t, results.GetFailed()[0].Traces(), 0)
	assert.Greater(t, len(traceBuffer.Bytes()), 0)
}

func Test_RegoScanning_PerResultTracingEnabled(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := NewScanner(types.SourceJSON, options.ScannerWithPerResultTracing(true))
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Greater(t, len(results.GetFailed()[0].Traces()), 0)
}

func Test_dynamicMetadata(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
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

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"text": "dynamic",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, results[0].Rule().Summary, "i am dynamic")
}

func Test_staticMetadata(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
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

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"text": "test",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, results[0].Rule().Summary, "i am static")
}

func Test_annotationMetadata(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
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

	scanner := NewScanner(types.SourceJSON)
	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
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

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `# METADATA
# schemas:
# - input: schema["input"]
package defsec.test

deny {
    input.evil == "lol"
}
`,
	})

	scanner := NewScanner(types.SourceDockerfile)
	scanner.SetRegoErrorLimit(0) // override to not allow any errors
	assert.ErrorContains(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
		"undefined ref: input.evil",
	)
}

func Test_RegoScanning_WithValidInputSchema(t *testing.T) {

	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `# METADATA
# schemas:
# - input: schema["input"]
package defsec.test

deny {
    input.Stages[0].Commands[0].Cmd == "lol"
}
`,
	})

	scanner := NewScanner(types.SourceDockerfile)
	assert.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)
}

func Test_RegoScanning_WithFilepathToSchema(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `# METADATA
# schemas:
# - input: schema["dockerfile"]
package defsec.test

deny {
    input.evil == "lol"
}
`,
	})
	scanner := NewScanner(types.SourceJSON)
	scanner.SetRegoErrorLimit(0) // override to not allow any errors
	assert.ErrorContains(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
		"undefined ref: input.evil",
	)
}

func Test_RegoScanning_CustomData(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test
import data.settings.DS123.foo_bar_baz

deny {
    not foo_bar_baz
}
`,
	})

	dataFS := CreateFS(t, map[string]string{
		"data/data.json": `{
	"settings": {
		"DS123":{
			"foo_bar_baz":false
		}
	}
}`,
		"data/junk.txt": "this file should be ignored",
	})

	scanner := NewScanner(types.SourceJSON)
	scanner.SetDataFilesystem(dataFS)
	scanner.SetDataDirs(".")

	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_InvalidFS(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test
import data.settings.DS123.foo_bar_baz

deny {
    not foo_bar_baz
}
`,
	})

	dataFS := CreateFS(t, map[string]string{
		"data/data.json": `{
	"settings": {
		"DS123":{
			"foo_bar_baz":false
		}
	}
}`,
		"data/junk.txt": "this file should be ignored",
	})

	scanner := NewScanner(types.SourceJSON)
	scanner.SetDataFilesystem(dataFS)
	scanner.SetDataDirs("X://")

	require.NoError(
		t,
		scanner.LoadPolicies(false, false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}
