package rego

import (
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	checks "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

func Test_EmbeddedLoading(t *testing.T) {
	LoadAndRegister()

	frameworkRules := rules.GetRegistered()
	var found bool
	for _, rule := range frameworkRules {
		if rule.GetRule().RegoPackage != "" {
			found = true
		}
	}
	assert.True(t, found, "no embedded rego policies were registered as rules")
}

func Test_RegisterRegoRules(t *testing.T) {
	var testCases = []struct {
		name          string
		inputPolicy   string
		expectedError bool
	}{
		{
			name: "happy path old single schema",
			inputPolicy: `# METADATA
# title: "dummy title"
# description: "some description"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
		},
		{
			name: "happy path new builtin single schema",
			inputPolicy: `# METADATA
# title: "dummy title"
# description: "some description"
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
		},
		{
			name: "happy path new multiple schemas",
			inputPolicy: `# METADATA
# title: "dummy title"
# description: "some description"
# scope: package
# schemas:
# - input: schema["dockerfile"]
# - input: schema["kubernetes"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policies, err := LoadPoliciesFromDirs(checks.EmbeddedLibraryFileSystem, ".")
			require.NoError(t, err)
			newRule, err := ast.ParseModuleWithOpts("/rules/newrule.rego", tc.inputPolicy, ast.ParserOptions{
				ProcessAnnotation: true,
			})
			require.NoError(t, err)

			policies["/rules/newrule.rego"] = newRule
			switch {
			case tc.expectedError:
				assert.Panics(t, func() {
					RegisterRegoRules(policies)
				}, tc.name)
			default:
				RegisterRegoRules(policies)
			}
		})
	}
}

func Test_RegisterDeprecatedRule(t *testing.T) {
	var testCases = []struct {
		name        string
		id          string
		inputPolicy string
		expected    scan.Rule
	}{
		{
			name: "deprecated check",
			id:   "AVD-DEP-0001",
			inputPolicy: `# METADATA
# title: "deprecated check"
# description: "some description"
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   avd_id: AVD-DEP-0001
#   input:
#     selector:
#     - type: dockerfile
#   deprecated: true
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
			expected: scan.Rule{
				Deprecated: true,
			},
		},
		{
			name: "not a deprecated check",
			id:   "AVD-NOTDEP-0001",
			inputPolicy: `# METADATA
# title: "not a deprecated check"
# description: "some description"
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   avd_id: AVD-NOTDEP-0001
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
			expected: scan.Rule{
				Deprecated: false,
			},
		},
		{
			name: "invalid deprecation value",
			id:   "AVD-BADDEP-0001",
			inputPolicy: `# METADATA
# title: "badly deprecated check"
# description: "some description"
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   avd_id: AVD-BADDEP-0001
#   input:
#     selector:
#     - type: dockerfile
#   deprecated: "this is bad, deprecation is a bool value not a string"
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
			expected: scan.Rule{
				Deprecated: false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policies := make(map[string]*ast.Module)
			newRule, err := ast.ParseModuleWithOpts("/rules/newrule.rego", tc.inputPolicy, ast.ParserOptions{
				ProcessAnnotation: true,
			})
			require.NoError(t, err)

			policies["/rules/newrule.rego"] = newRule
			assert.NotPanics(t, func() {
				RegisterRegoRules(policies)
			})

			for _, rule := range rules.GetRegistered() {
				if rule.AVDID == tc.id {
					assert.Equal(t, tc.expected.Deprecated, rule.GetRule().Deprecated, tc.name)
				}
			}
		})
	}
}
