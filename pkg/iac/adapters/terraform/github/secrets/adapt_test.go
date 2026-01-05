package secrets

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/github"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []github.EnvironmentSecret
	}{
		{
			name: "basic",
			terraform: `
resource "github_actions_environment_secret" "example" {
}
`,
			expected: []github.EnvironmentSecret{
				{},
			},
		},
		{
			name: "basic",
			terraform: `
resource "github_actions_environment_secret" "example" {
    secret_name     = "a"
	plaintext_value = "b"
	environment     = "c"
	encrypted_value = "d"
	repository      = "e"
}
`,
			expected: []github.EnvironmentSecret{
				{
					SecretName:     iacTypes.StringTest("a"),
					PlainTextValue: iacTypes.StringTest("b"),
					Environment:    iacTypes.StringTest("c"),
					EncryptedValue: iacTypes.StringTest("d"),
					Repository:     iacTypes.StringTest("e"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
