package secrets

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/github"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
				{
					Metadata:       defsecTypes.NewTestMetadata(),
					Environment:    defsecTypes.String("", defsecTypes.NewTestMetadata()),
					SecretName:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
					PlainTextValue: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					EncryptedValue: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Repository:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
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
					Metadata:       defsecTypes.NewTestMetadata(),
					SecretName:     defsecTypes.String("a", defsecTypes.NewTestMetadata()),
					PlainTextValue: defsecTypes.String("b", defsecTypes.NewTestMetadata()),
					Environment:    defsecTypes.String("c", defsecTypes.NewTestMetadata()),
					EncryptedValue: defsecTypes.String("d", defsecTypes.NewTestMetadata()),
					Repository:     defsecTypes.String("e", defsecTypes.NewTestMetadata()),
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
