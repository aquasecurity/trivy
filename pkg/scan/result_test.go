package scan_test

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func Test_Occurrences(t *testing.T) {
	tests := []struct {
		name     string
		factory  func() *scan.Result
		expected []scan.Occurrence
	}{
		{
			name: "happy",
			factory: func() *scan.Result {
				r := scan.Result{}
				causeResourceMeta := types.NewMisconfigMetadata(types.NewRange(
					"main.tf", 1, 13, "", nil,
				), "module.aws-security-groups[\"db1\"]")

				parentMeta := types.NewMisconfigMetadata(types.NewRange(
					"terraform-aws-modules/security-group/aws/main.tf", 191, 227, "", nil,
				), "aws_security_group_rule.ingress_with_cidr_blocks[0]").WithParent(causeResourceMeta)

				r.OverrideMetadata(types.NewMisconfigMetadata(types.NewRange(
					"terraform-aws-modules/security-group/aws/main.tf", 197, 204, "", nil,
				), "aws_security_group_rule.ingress_with_cidr_blocks").WithParent(parentMeta))
				return &r
			},
			expected: []scan.Occurrence{
				{
					Resource:  "aws_security_group_rule.ingress_with_cidr_blocks[0]",
					Filename:  "terraform-aws-modules/security-group/aws/main.tf",
					StartLine: 191,
					EndLine:   227,
				},
				{
					Resource:  "module.aws-security-groups[\"db1\"]",
					Filename:  "main.tf",
					StartLine: 1,
					EndLine:   13,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.factory().Occurrences())
		})
	}
}
