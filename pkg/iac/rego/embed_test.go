package rego

import (
	"testing"

	rules2 "github.com/aquasecurity/trivy-policies"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EmbeddedLoading(t *testing.T) {

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
		{
			name: "sad path schema does not exist",
			inputPolicy: `# METADATA
# title: "dummy title"
# description: "some description"
# scope: package
# schemas:
# - input: schema["invalid schema"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policies, err := LoadPoliciesFromDirs(rules2.EmbeddedLibraryFileSystem, ".")
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
