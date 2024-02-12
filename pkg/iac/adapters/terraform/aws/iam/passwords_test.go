package iam

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
)

func Test_adaptPasswordPolicy(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.PasswordPolicy
	}{
		{
			name: "basic",
			terraform: `
			resource "aws_iam_account_password_policy" "strict" {
				minimum_password_length        = 8
				require_lowercase_characters   = true
				require_numbers                = true
				require_uppercase_characters   = true
				require_symbols                = true
				allow_users_to_change_password = true
				max_password_age               = 90
				password_reuse_prevention      = 3
			  }
`,
			expected: iam.PasswordPolicy{
				Metadata:             defsecTypes.NewTestMetadata(),
				ReusePreventionCount: defsecTypes.Int(3, defsecTypes.NewTestMetadata()),
				RequireLowercase:     defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				RequireUppercase:     defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				RequireNumbers:       defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				RequireSymbols:       defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				MaxAgeDays:           defsecTypes.Int(90, defsecTypes.NewTestMetadata()),
				MinimumLength:        defsecTypes.Int(8, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPasswordPolicy(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
