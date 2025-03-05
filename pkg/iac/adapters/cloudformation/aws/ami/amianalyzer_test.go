package ami

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ami"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAMI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ami.AMI
	}{
		{
			name: "AMI with owner",
			input: `
Resources:
 MyAMI:
   Type: 'AWS::EC2::Image'
   Properties:
     Owners: amazon`,
			expected: ami.AMI{
				Metadata: iacTypes.NewTestMetadata(),
				Owners: iacTypes.StringValueList{
					iacTypes.StringTest("amazon"),
				},
			},
		},
		{
			name: "AMI without owner",
			input: `
Resources:
 MyAMI:
   Type: 'AWS::EC2::Image'
   Properties:
     Name: test-ami`,
			expected: ami.AMI{
				Metadata: iacTypes.NewTestMetadata(),
				Owners:   iacTypes.StringValueList{iacTypes.StringTest("")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.input, tt.expected, Adapt)
		})
	}
}
