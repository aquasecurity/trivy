package secrets

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/github"

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
					Metadata:       defsecTypes.NewTestMisconfigMetadata(),
					Environment:    defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					SecretName:     defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					PlainTextValue: defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					EncryptedValue: defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					Repository:     defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
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
					Metadata:       defsecTypes.NewTestMisconfigMetadata(),
					SecretName:     defsecTypes.String("a", defsecTypes.NewTestMisconfigMetadata()),
					PlainTextValue: defsecTypes.String("b", defsecTypes.NewTestMisconfigMetadata()),
					Environment:    defsecTypes.String("c", defsecTypes.NewTestMisconfigMetadata()),
					EncryptedValue: defsecTypes.String("d", defsecTypes.NewTestMisconfigMetadata()),
					Repository:     defsecTypes.String("e", defsecTypes.NewTestMisconfigMetadata()),
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
