package generic_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/generic"
)

func TestJsonScanner(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
		"/code/data.json": `{ "x": { "y": 123, "z": ["a", "b", "c"]}}`,
		"/rules/rule.rego": `package builtin.json.lol

__rego_metadata__ := {
	"id": "ABC123",
	"avd_id": "AVD-AB-0123",
	"title": "title",
	"short_code": "short",
	"severity": "CRITICAL",
	"type": "JSON Check",
	"description": "description",
	"recommended_actions": "actions",
	"url": "https://example.com",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "json"}],
}

deny[res] {
	input.x.y == 123
	res := {
		"msg": "oh no",
		"startline": 1,
		"endline": 2,
	}
}

`,
	})

	scanner := generic.NewJsonScanner(rego.WithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fsys, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	assert.Equal(t, scan.Rule{
		AVDID:          "AVD-AB-0123",
		Aliases:        []string{"ABC123"},
		ShortCode:      "short",
		Summary:        "title",
		Explanation:    "description",
		Impact:         "",
		Resolution:     "actions",
		Provider:       "json",
		Service:        "general",
		Links:          []string{"https://example.com"},
		Severity:       "CRITICAL",
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		RegoPackage:    "data.builtin.json.lol",
		Frameworks: map[framework.Framework][]string{
			framework.Default: {},
		},
	}, results.GetFailed()[0].Rule())
}

func TestYamlScanner(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
		"/code/data.yaml": `---
x:
  y: 123
  z:
  - a
  - b
  - c
`,
		"/rules/rule.rego": `package builtin.yaml.lol

__rego_metadata__ := {
	"id": "ABC123",
	"avd_id": "AVD-AB-0123",
	"title": "title",
	"short_code": "short",
	"severity": "CRITICAL",
	"type": "YAML Check",
	"description": "description",
	"recommended_actions": "actions",
	"url": "https://example.com",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "yaml"}],
}

deny[res] {
	input.x.y == 123
	res := {
		"msg": "oh no",
		"startline": 1,
		"endline": 2,
	}
}

`,
	})

	scanner := generic.NewYamlScanner(rego.WithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fsys, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	assert.Equal(t, scan.Rule{
		AVDID:          "AVD-AB-0123",
		Aliases:        []string{"ABC123"},
		ShortCode:      "short",
		Summary:        "title",
		Explanation:    "description",
		Impact:         "",
		Resolution:     "actions",
		Provider:       "yaml",
		Service:        "general",
		Links:          []string{"https://example.com"},
		Severity:       "CRITICAL",
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		RegoPackage:    "data.builtin.yaml.lol",
		Frameworks: map[framework.Framework][]string{
			framework.Default: {},
		},
	},
		results.GetFailed()[0].Rule(),
	)
}

func TestTomlParser(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
		"/code/code.toml": `
[x]
y = 123
z = ["a", "b", "c"]
`,
		"/rules/rule.rego": `package builtin.toml.lol

__rego_metadata__ := {
	"id": "ABC123",
	"avd_id": "AVD-AB-0123",
	"title": "title",
	"short_code": "short",
	"severity": "CRITICAL",
	"type": "TOML Check",
	"description": "description",
	"recommended_actions": "actions",
	"url": "https://example.com",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "toml"}],
}

deny[res] {
	input.x.y == 123
	res := {
		"msg": "oh no",
		"startline": 1,
		"endline": 2,
	}
}

`,
	})

	scanner := generic.NewTomlScanner(rego.WithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fsys, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	assert.Equal(t, scan.Rule{
		AVDID:          "AVD-AB-0123",
		Aliases:        []string{"ABC123"},
		ShortCode:      "short",
		Summary:        "title",
		Explanation:    "description",
		Impact:         "",
		Resolution:     "actions",
		Provider:       "toml",
		Service:        "general",
		Links:          []string{"https://example.com"},
		Severity:       "CRITICAL",
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		RegoPackage:    "data.builtin.toml.lol",
		Frameworks: map[framework.Framework][]string{
			framework.Default: {},
		},
	},
		results.GetFailed()[0].Rule(),
	)
}
