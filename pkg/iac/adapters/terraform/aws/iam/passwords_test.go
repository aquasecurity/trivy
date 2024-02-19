package iam

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

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
				Metadata:             iacTypes.NewTestMetadata(),
				ReusePreventionCount: iacTypes.Int(3, iacTypes.NewTestMetadata()),
				RequireLowercase:     iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				RequireUppercase:     iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				RequireNumbers:       iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				RequireSymbols:       iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				MaxAgeDays:           iacTypes.Int(90, iacTypes.NewTestMetadata()),
				MinimumLength:        iacTypes.Int(8, iacTypes.NewTestMetadata()),
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
