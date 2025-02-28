package table_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMisconfigRenderer(t *testing.T) {
	type args struct {
		includeNonFailures bool
		renderCause        []ftypes.ConfigType
	}
	tests := []struct {
		name  string
		input types.Result
		args  args
		want  string
	}{
		{
			name: "single result",
			input: types.Result{
				Target:         "my-file",
				MisconfSummary: &types.MisconfSummary{Successes: 0, Failures: 1},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:          "some-alias-for-a-check",
						AVDID:       "AVD-XYZ-0123",
						Title:       "Config file is bad",
						Description: "Your config file is not good.",
						Message:     "Oh no, a bad config.",
						Severity:    "HIGH",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "FAIL",
					},
				},
			},
			args: args{
				includeNonFailures: false,
			},
			want: `
my-file ()
==========
Tests: 1 (SUCCESSES: 0, FAILURES: 1)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

AVD-XYZ-0123 (HIGH): Oh no, a bad config.
════════════════════════════════════════
Your config file is not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────


`,
		},
		{
			name: "single result with code",
			input: types.Result{
				Target:         "my-file",
				MisconfSummary: &types.MisconfSummary{Successes: 0, Failures: 1},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						AVDID:       "AVD-XYZ-0123",
						Title:       "Config file is bad",
						Description: "Your config file is not good.",
						Message:     "Oh no, a bad config.",
						Severity:    "HIGH",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "FAIL",
						CauseMetadata: ftypes.CauseMetadata{
							Resource:  "",
							Provider:  "",
							Service:   "",
							StartLine: 0,
							EndLine:   0,
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number: 1,
									},
									{
										Number:      2,
										Content:     "bad: true",
										Highlighted: "\x1b[37mbad:\x1b[0m true",
										IsCause:     true,
										FirstCause:  true,
										LastCause:   true,
									},
									{
										Number: 3,
									},
								},
							},
						},
					},
				},
			},
			args: args{
				includeNonFailures: false,
			},
			want: `
my-file ()
==========
Tests: 1 (SUCCESSES: 0, FAILURES: 1)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

AVD-XYZ-0123 (HIGH): Oh no, a bad config.
════════════════════════════════════════
Your config file is not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────
 my-file
────────────────────────────────────────
   1   
   2 [ bad: true
   3   
────────────────────────────────────────


`,
		},
		{
			name: "multiple results",
			input: types.Result{
				Target:         "my-file",
				MisconfSummary: &types.MisconfSummary{Successes: 1, Failures: 1},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						AVDID:       "AVD-XYZ-0123",
						Title:       "Config file is bad",
						Description: "Your config file is not good.",
						Message:     "Oh no, a bad config.",
						Severity:    "HIGH",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "FAIL",
						CauseMetadata: ftypes.CauseMetadata{
							StartLine: 2,
							EndLine:   2,
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number: 1,
									},
									{
										Number:      2,
										Content:     "bad: true",
										Highlighted: "\x1b[37mbad:\x1b[0m true",
										IsCause:     true,
										FirstCause:  true,
										LastCause:   true,
									},
									{
										Number: 3,
									},
								},
							},
						},
					},
					{
						AVDID:       "AVD-XYZ-0456",
						Title:       "Config file is bad again",
						Description: "Your config file is still not good.",
						Message:     "Oh no, a bad config AGAIN.",
						Severity:    "MEDIUM",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "PASS",
					},
				},
			},
			args: args{
				includeNonFailures: true,
			},
			want: `
my-file ()
==========
Tests: 2 (SUCCESSES: 1, FAILURES: 1)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

FAIL: AVD-XYZ-0123 (HIGH): Oh no, a bad config.
════════════════════════════════════════
Your config file is not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────
 my-file:2
────────────────────────────────────────
   1   
   2 [ bad: true
   3   
────────────────────────────────────────


PASS: AVD-XYZ-0456 (MEDIUM): Oh no, a bad config AGAIN.
════════════════════════════════════════
Your config file is still not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────


`,
		},
		{
			name: "resource name in report",
			input: types.Result{
				Target: "terraform-aws-modules/security-group/aws/main.tf",
				Class:  types.ClassConfig,
				Type:   ftypes.Terraform,
				MisconfSummary: &types.MisconfSummary{
					Successes: 5,
					Failures:  1,
				},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						Type:        "Terraform Security Check",
						ID:          "AVD-AWS-0107",
						AVDID:       "AVD-AWS-0107",
						Title:       "An ingress security group rule allows traffic from /0",
						Description: "Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.",
						Message:     "Security group rule allows ingress from public internet.",
						Query:       "data..",
						Resolution:  "Set a more restrictive cidr range",
						Severity:    "CRITICAL",
						PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-aws-0107",
						References: []string{
							"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
							"https://avd.aquasec.com/misconfig/avd-aws-0107",
						},
						Status: "FAIL",
						CauseMetadata: ftypes.CauseMetadata{
							Resource:  "module.aws-security-groups[\"db1\"]",
							Provider:  "AWS",
							Service:   "ec2",
							StartLine: 197,
							EndLine:   204,
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number:  191,
										Content: "resource \"aws_security_group_rule\" \"ingress_with_cidr_blocks\" {",
										IsCause: false,
									},
									{
										Number:    192,
										Truncated: true,
									},
									{
										Number:    197,
										Truncated: true,
									},
									{
										Number:  198,
										Content: "    \",\",",
										IsCause: true,
									},
									{
										Number:  199,
										Content: "    lookup(",
										IsCause: true,
									},
									{
										Number:  200,
										Content: "      var.ingress_with_cidr_blocks[count.index],",
										IsCause: true,
									},
									{
										Number:  201,
										Content: "      \"cidr_blocks\",",
										IsCause: true,
									},
									{
										Number:  202,
										Content: "      join(\",\", var.ingress_cidr_blocks),",
										IsCause: true,
									},
									{
										Number:    203,
										Content:   "    ),",
										IsCause:   true,
										LastCause: true,
									},
									{
										Number:    204,
										Truncated: true,
									},
								},
							},
							Occurrences: []ftypes.Occurrence{
								{
									Resource: "aws_security_group_rule.ingress_with_cidr_blocks[0]",
									Filename: "terraform-aws-modules/security-group/aws/main.tf",
									Location: ftypes.Location{
										StartLine: 191,
										EndLine:   227,
									},
								},
								{
									Resource: "module.aws-security-groups[\"db1\"]",
									Filename: "sg.tf",
									Location: ftypes.Location{
										StartLine: 1,
										EndLine:   13,
									},
								},
							},
							RenderedCause: ftypes.RenderedCause{
								Raw: "resource \"aws_security_group_rule\" \"ingress_with_cidr_blocks\" {\n  cidr_blocks = [ \"0.0.0.0/0\" ]\n}",
							},
						},
					},
				},
			},
			want: `
terraform-aws-modules/security-group/aws/main.tf (terraform)
============================================================
Tests: 6 (SUCCESSES: 5, FAILURES: 1)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)

AVD-AWS-0107 (CRITICAL): Security group rule allows ingress from public internet.
════════════════════════════════════════
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.

See https://avd.aquasec.com/misconfig/avd-aws-0107
────────────────────────────────────────
 terraform-aws-modules/security-group/aws/main.tf:197-204
   via terraform-aws-modules/security-group/aws/main.tf:191-227 (aws_security_group_rule.ingress_with_cidr_blocks[0])
    via sg.tf:1-13 (module.aws-security-groups["db1"])
────────────────────────────────────────
 191   resource "aws_security_group_rule" "ingress_with_cidr_blocks" {
 ...   
 ...   
 198 │     ",",
 199 │     lookup(
 200 │       var.ingress_with_cidr_blocks[count.index],
 201 │       "cidr_blocks",
 202 │       join(",", var.ingress_cidr_blocks),
 203 └     ),
 ...   
────────────────────────────────────────


`,
		},
		{
			name: "with rendered cause",
			args: args{
				renderCause: []ftypes.ConfigType{ftypes.Terraform},
			},
			input: types.Result{
				Target:         "main.tf",
				Class:          types.ClassConfig,
				Type:           ftypes.Terraform,
				MisconfSummary: &types.MisconfSummary{Failures: 1},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						Type:        "Terraform Security Check",
						ID:          "AVD-AWS-0320",
						AVDID:       "AVD-AWS-0320",
						Title:       "S3 DNS Compliant Bucket Names",
						Description: "Ensures that S3 buckets have DNS complaint bucket names.",
						Message:     "S3 bucket name is not compliant with DNS naming requirements",
						Namespace:   "builtin.aws.s3.aws0320",
						Query:       "data.builtin.aws.s3.aws0320.deny",
						Resolution:  "Recreate S3 bucket to use - instead of . in S3 bucket names",
						Severity:    "MEDIUM",
						PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-aws-0320",
						References: []string{
							"https://docs.aws.amazon.com/AmazonS3/latest./dev/transfer-acceleration.html",
							"https://avd.aquasec.com/misconfig/avd-aws-0320",
						},
						Status: "FAIL",
						CauseMetadata: ftypes.CauseMetadata{
							Resource:  "aws_s3_bucket.this",
							Provider:  "AWS",
							Service:   "s3",
							StartLine: 6,
							EndLine:   6,
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number:  5,
										Content: "resource \"aws_s3_bucket\" \"this\" {",
									},
									{
										Number:  6,
										Content: "    bucket = local.bucket",
										IsCause: true,
									},
									{
										Number:  7,
										Content: "}",
									},
								},
							},
							Occurrences: []ftypes.Occurrence{
								{
									Resource: "aws_s3_bucket.this",
									Filename: "main.tf",
									Location: ftypes.Location{
										StartLine: 5,
										EndLine:   7,
									},
								},
							},
							RenderedCause: ftypes.RenderedCause{
								Raw: "resource \"aws_s3_bucket\" \"this\" {\n  bucket = \"foo.bar\"\n}",
							},
						},
					},
				},
			},
			want: `
main.tf (terraform)
===================
Tests: 1 (SUCCESSES: 0, FAILURES: 1)
Failures: 1 (LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

AVD-AWS-0320 (MEDIUM): S3 bucket name is not compliant with DNS naming requirements
════════════════════════════════════════
Ensures that S3 buckets have DNS complaint bucket names.

See https://avd.aquasec.com/misconfig/avd-aws-0320
────────────────────────────────────────
 main.tf:6
   via main.tf:5-7 (aws_s3_bucket.this)
────────────────────────────────────────
   5   resource "aws_s3_bucket" "this" {
   6 │     bucket = local.bucket
   7   }
────────────────────────────────────────
Rendered cause:
────────────────────────────────────────
resource "aws_s3_bucket" "this" {
  bucket = "foo.bar"
}
────────────────────────────────────────


`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severities := []dbTypes.Severity{
				dbTypes.SeverityLow, dbTypes.SeverityMedium, dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			}
			buf := bytes.NewBuffer([]byte{})
			renderer := table.NewMisconfigRenderer(buf, severities, false, tt.args.includeNonFailures, false, tt.args.renderCause)
			renderer.Render(tt.input)
			assert.Equal(t, tt.want, strings.ReplaceAll(buf.String(), "\r\n", "\n"))
		})
	}
}
