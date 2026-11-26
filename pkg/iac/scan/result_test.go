package scan_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/types"
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
				causeResourceMeta := types.NewMetadata(types.NewRange(
					"main.tf", 1, 13, "", nil,
				), "module.aws-security-groups[\"db1\"]")

				parentMeta := types.NewMetadata(types.NewRange(
					"terraform-aws-modules/security-group/aws/main.tf", 191, 227, "", nil,
				), "aws_security_group_rule.ingress_with_cidr_blocks[0]").WithParent(causeResourceMeta)

				r.OverrideMetadata(types.NewMetadata(types.NewRange(
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

func TestResult_Fingerprint(t *testing.T) {
	const (
		modFile   = "modules/sg/main.tf"
		causeRef  = "aws_security_group_rule.this.cidr_blocks"
		moduleRef = "module.sg"
	)

	newResult := func(shift int, causeRef, moduleRef string) *scan.Result {
		moduleMeta := types.NewMetadata(types.NewRange("main.tf", 1, 3, "", nil), moduleRef)
		resourceMeta := types.NewMetadata(
			types.NewRange(modFile, shift+1, shift+10, "", nil), "aws_security_group_rule.this",
		).WithParent(moduleMeta)

		var r scan.Result
		r.SetRule(scan.Rule{ID: "AWS-0104"})
		r.OverrideMetadata(types.NewMetadata(
			types.NewRange(modFile, shift+5, shift+5, "", nil), causeRef,
		).WithParent(resourceMeta))
		return &r
	}

	tests := []struct {
		name  string
		a     *scan.Result
		b     *scan.Result
		equal bool
	}{
		{
			name: "different count keys",
			a:    newResult(0, causeRef, moduleRef+"[0]"),
			b:    newResult(0, causeRef, moduleRef+"[1]"),
		},
		{
			name: "different for_each keys",
			a:    newResult(0, causeRef, moduleRef+`["dev"]`),
			b:    newResult(0, causeRef, moduleRef+`["prod"]`),
		},
		{
			name: "different cause refs",
			a:    newResult(0, causeRef, moduleRef),
			b:    newResult(0, "aws_security_group_rule.this.description", moduleRef),
		},
		{
			name:  "shifted lines",
			a:     newResult(0, causeRef, moduleRef),
			b:     newResult(20, causeRef, moduleRef),
			equal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := tt.a.Fingerprint(), tt.b.Fingerprint()
			assert.NotEmpty(t, a)
			assert.NotEmpty(t, b)
			if tt.equal {
				assert.Equal(t, a, b)
			} else {
				assert.NotEqual(t, a, b)
			}
		})
	}

	t.Run("no refs", func(t *testing.T) {
		var r scan.Result
		r.SetRule(scan.Rule{ID: "KSV-0001"})
		r.OverrideMetadata(types.NewMetadata(
			types.NewRange("deploy.yaml", 5, 5, "", nil), "",
		).WithParent(types.NewMetadata(types.NewRange("deploy.yaml", 1, 20, "", nil), "")))
		assert.Empty(t, r.Fingerprint())
	})
}
