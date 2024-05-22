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
				{
					Metadata:       iacTypes.NewTestMetadata(),
					Environment:    iacTypes.String("", iacTypes.NewTestMetadata()),
					SecretName:     iacTypes.String("", iacTypes.NewTestMetadata()),
					PlainTextValue: iacTypes.String("", iacTypes.NewTestMetadata()),
					EncryptedValue: iacTypes.String("", iacTypes.NewTestMetadata()),
					Repository:     iacTypes.String("", iacTypes.NewTestMetadata()),
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
					Metadata:       iacTypes.NewTestMetadata(),
					SecretName:     iacTypes.String("a", iacTypes.NewTestMetadata()),
					PlainTextValue: iacTypes.String("b", iacTypes.NewTestMetadata()),
					Environment:    iacTypes.String("c", iacTypes.NewTestMetadata()),
					EncryptedValue: iacTypes.String("d", iacTypes.NewTestMetadata()),
					Repository:     iacTypes.String("e", iacTypes.NewTestMetadata()),
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
