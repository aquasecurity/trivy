package table_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMisconfigRenderer(t *testing.T) {

	tests := []struct {
		name               string
		input              types.Result
		includeNonFailures bool
		want               string
	}{
		{
			name: "single result",
			input: types.Result{
				Target:         "my-file",
				MisconfSummary: &types.MisconfSummary{Successes: 0, Failures: 1, Exceptions: 0},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:          "AVD-XYZ-0123",
						Title:       "Config file is bad",
						Description: "Your config file is not good.",
						Message:     "Oh no, a bad config.",
						Severity:    "HIGH",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "FAIL",
					},
				},
			},
			includeNonFailures: false,
			want: `
my-file ()
==========
Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: Oh no, a bad config.
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
				MisconfSummary: &types.MisconfSummary{Successes: 0, Failures: 1, Exceptions: 0},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:          "AVD-XYZ-0123",
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
			includeNonFailures: false,
			want: `
my-file ()
==========
Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: Oh no, a bad config.
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
				MisconfSummary: &types.MisconfSummary{Successes: 1, Failures: 1, Exceptions: 0},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:          "AVD-XYZ-0123",
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
						ID:          "AVD-XYZ-0456",
						Title:       "Config file is bad again",
						Description: "Your config file is still not good.",
						Message:     "Oh no, a bad config AGAIN.",
						Severity:    "MEDIUM",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "PASS",
					},
				},
			},
			includeNonFailures: true,
			want: `
my-file ()
==========
Tests: 2 (SUCCESSES: 1, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

FAIL: HIGH: Oh no, a bad config.
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


PASS: MEDIUM: Oh no, a bad config AGAIN.
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
				Type:   "terraform",
				MisconfSummary: &types.MisconfSummary{
					Successes:  5,
					Failures:   1,
					Exceptions: 0,
				},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						Type:        "Terraform Security Check",
						ID:          "AVD-AWS-0107",
						AVDID:       "AVS-AWS-0107",
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
						},
					},
				},
			},
			want: `
terraform-aws-modules/security-group/aws/main.tf (terraform)
============================================================
Tests: 6 (SUCCESSES: 5, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)

CRITICAL: Security group rule allows ingress from public internet.
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			severities := []dbTypes.Severity{dbTypes.SeverityLow, dbTypes.SeverityMedium, dbTypes.SeverityHigh,
				dbTypes.SeverityCritical}
			renderer := table.NewMisconfigRenderer(test.input, severities, false, test.includeNonFailures, false)
			assert.Equal(t, test.want, strings.ReplaceAll(renderer.Render(), "\r\n", "\n"))
		})
	}
}
