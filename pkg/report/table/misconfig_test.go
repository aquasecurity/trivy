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
		name  string
		input types.Result
		opts  []table.MisconfRendererOption
		want  string
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
						Severity:    dbTypes.SeverityHigh.String(),
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      types.StatusFailure,
					},
				},
			},
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
						Severity:    dbTypes.SeverityHigh.String(),
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      types.StatusFailure,
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
						Severity:    dbTypes.SeverityMedium.String(),
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      types.StatusPassed,
					},
				},
			},
			opts: []table.MisconfRendererOption{table.WithIncludeNonFailures(true)},
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
						Severity:    dbTypes.SeverityCritical.String(),
						PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-aws-0107",
						References: []string{
							"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
							"https://avd.aquasec.com/misconfig/avd-aws-0107",
						},
						Status: types.StatusFailure,
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
		{
			name: "with grouping",
			input: types.Result{
				Target:         "main.tf",
				Class:          types.ClassConfig,
				Type:           "terraform",
				MisconfSummary: &types.MisconfSummary{Successes: 1, Failures: 2, Exceptions: 0},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						Type:        "Terraform Security Check",
						ID:          "AVD-GCP-0013",
						AVDID:       "AVD-GCP-0013",
						Title:       "Cloud DNS should use DNSSEC",
						Description: "DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.",
						Message:     "Managed zone does not have DNSSEC enabled.",
						Resolution:  "Enable DNSSEC",
						Severity:    dbTypes.SeverityMedium.String(),
						PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-gcp-0013",
						Status:      types.StatusFailure,
						CauseMetadata: ftypes.CauseMetadata{
							Resource:  "google_dns_managed_zone.this[0]",
							Provider:  "Google",
							Service:   "dns",
							StartLine: 16,
							EndLine:   16,
							Occurrences: []ftypes.Occurrence{
								{
									Resource: "dnssec_config",
									Filename: "main.tf",
									Location: ftypes.Location{
										StartLine: 15,
										EndLine:   17,
									},
								},
								{
									Resource: "google_dns_managed_zone.this[0]",
									Filename: "main.tf",
									Location: ftypes.Location{
										StartLine: 9,
										EndLine:   18,
									},
								},
							},
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number:      9,
										Content:     "resource \"google_dns_managed_zone\" \"this\" {",
										Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"google_dns_managed_zone\"\x1b[0m \x1b[38;5;37m\"this\"\x1b[0m {",
									},
									{
										Number:      10,
										Content:     "  count       = 3",
										Highlighted: "  \x1b[38;5;245mcount\x1b[0m       = \x1b[38;5;37m3"},
									{
										Number:      11,
										Content:     "  name        = \"example-zone-${count.index}\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mname\x1b[0m        = \x1b[38;5;37m\"example-zone-\x1b[0m\x1b[38;5;37m${\x1b[0m\x1b[38;5;33mcount\x1b[0m.index\x1b[38;5;37m}\x1b[0m\x1b[38;5;37m\"",
									},
									{
										Number:      12,
										Content:     "  dns_name    = \"example-${random_id.dns.hex}.com.\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mdns_name\x1b[0m    = \x1b[38;5;37m\"example-\x1b[0m\x1b[38;5;37m${\x1b[0mrandom_id.dns.hex\x1b[38;5;37m}\x1b[0m\x1b[38;5;37m.com.\"",
									},
									{
										Number:      13,
										Content:     "  description = \"Example DNS zone\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mdescription\x1b[0m = \x1b[38;5;37m\"Example DNS zone\"",
									},
									{
										Number:      14,
										Content:     "",
										Highlighted: "\x1b[0m",
									},
									{
										Number:      15,
										Content:     "  dnssec_config {",
										Highlighted: "  dnssec_config {",
									},
									{
										Number:      16,
										Content:     "    state = local.dnssec_state[count.index]",
										IsCause:     true,
										Highlighted: "    \x1b[38;5;245mstate\x1b[0m = local.dnssec_state[\x1b[38;5;33mcount\x1b[0m.index]",
										FirstCause:  true,
										LastCause:   true,
									},
									{
										Number:      17,
										Content:     "  }",
										Highlighted: "  }",
									},
									{
										Number:      18,
										Content:     "}",
										Highlighted: "}",
									},
								},
							},
						},
					},
					{
						Type:        "Terraform Security Check",
						ID:          "AVD-GCP-0013",
						AVDID:       "AVD-GCP-0013",
						Title:       "Cloud DNS should use DNSSEC",
						Description: "DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.",
						Message:     "Managed zone does not have DNSSEC enabled.",
						Resolution:  "Enable DNSSEC",
						Severity:    dbTypes.SeverityMedium.String(),
						PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-gcp-0013",
						Status:      types.StatusFailure,
						CauseMetadata: ftypes.CauseMetadata{
							Resource:  "google_dns_managed_zone.this[0]",
							Provider:  "Google",
							Service:   "dns",
							StartLine: 16,
							EndLine:   16,
							Occurrences: []ftypes.Occurrence{
								{
									Resource: "dnssec_config",
									Filename: "main.tf",
									Location: ftypes.Location{
										StartLine: 15,
										EndLine:   17,
									},
								},
								{
									Resource: "google_dns_managed_zone.this[0]",
									Filename: "main.tf",
									Location: ftypes.Location{
										StartLine: 9,
										EndLine:   18,
									},
								},
							},
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number:      9,
										Content:     "resource \"google_dns_managed_zone\" \"this\" {",
										Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"google_dns_managed_zone\"\x1b[0m \x1b[38;5;37m\"this\"\x1b[0m {",
									},
									{
										Number:      10,
										Content:     "  count       = 3",
										Highlighted: "  \x1b[38;5;245mcount\x1b[0m       = \x1b[38;5;37m3"},
									{
										Number:      11,
										Content:     "  name        = \"example-zone-${count.index}\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mname\x1b[0m        = \x1b[38;5;37m\"example-zone-\x1b[0m\x1b[38;5;37m${\x1b[0m\x1b[38;5;33mcount\x1b[0m.index\x1b[38;5;37m}\x1b[0m\x1b[38;5;37m\"",
									},
									{
										Number:      12,
										Content:     "  dns_name    = \"example-${random_id.dns.hex}.com.\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mdns_name\x1b[0m    = \x1b[38;5;37m\"example-\x1b[0m\x1b[38;5;37m${\x1b[0mrandom_id.dns.hex\x1b[38;5;37m}\x1b[0m\x1b[38;5;37m.com.\"",
									},
									{
										Number:      13,
										Content:     "  description = \"Example DNS zone\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mdescription\x1b[0m = \x1b[38;5;37m\"Example DNS zone\"",
									},
									{
										Number:      14,
										Content:     "",
										Highlighted: "\x1b[0m",
									},
									{
										Number:      15,
										Content:     "  dnssec_config {",
										Highlighted: "  dnssec_config {",
									},
									{
										Number:      16,
										Content:     "    state = local.dnssec_state[count.index]",
										IsCause:     true,
										Highlighted: "    \x1b[38;5;245mstate\x1b[0m = local.dnssec_state[\x1b[38;5;33mcount\x1b[0m.index]",
										FirstCause:  true,
										LastCause:   true,
									},
									{
										Number:      17,
										Content:     "  }",
										Highlighted: "  }",
									},
									{
										Number:      18,
										Content:     "}",
										Highlighted: "}",
									},
								},
							},
						},
					},
					{
						Type:        "Terraform Security Check",
						ID:          "AVD-GCP-0013",
						AVDID:       "AVD-GCP-0013",
						Title:       "Cloud DNS should use DNSSEC",
						Description: "DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.",
						Message:     "Managed zone does not have DNSSEC enabled.",
						Resolution:  "Enable DNSSEC",
						Severity:    dbTypes.SeverityMedium.String(),
						PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-gcp-0013",
						Status:      types.StatusPassed,
						CauseMetadata: ftypes.CauseMetadata{
							Resource:  "google_dns_managed_zone.this[0]",
							Provider:  "Google",
							Service:   "dns",
							StartLine: 16,
							EndLine:   16,
							Occurrences: []ftypes.Occurrence{
								{
									Resource: "dnssec_config",
									Filename: "main.tf",
									Location: ftypes.Location{
										StartLine: 15,
										EndLine:   17,
									},
								},
								{
									Resource: "google_dns_managed_zone.this[0]",
									Filename: "main.tf",
									Location: ftypes.Location{
										StartLine: 9,
										EndLine:   18,
									},
								},
							},
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number:      9,
										Content:     "resource \"google_dns_managed_zone\" \"this\" {",
										Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"google_dns_managed_zone\"\x1b[0m \x1b[38;5;37m\"this\"\x1b[0m {",
									},
									{
										Number:      10,
										Content:     "  count       = 3",
										Highlighted: "  \x1b[38;5;245mcount\x1b[0m       = \x1b[38;5;37m3"},
									{
										Number:      11,
										Content:     "  name        = \"example-zone-${count.index}\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mname\x1b[0m        = \x1b[38;5;37m\"example-zone-\x1b[0m\x1b[38;5;37m${\x1b[0m\x1b[38;5;33mcount\x1b[0m.index\x1b[38;5;37m}\x1b[0m\x1b[38;5;37m\"",
									},
									{
										Number:      12,
										Content:     "  dns_name    = \"example-${random_id.dns.hex}.com.\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mdns_name\x1b[0m    = \x1b[38;5;37m\"example-\x1b[0m\x1b[38;5;37m${\x1b[0mrandom_id.dns.hex\x1b[38;5;37m}\x1b[0m\x1b[38;5;37m.com.\"",
									},
									{
										Number:      13,
										Content:     "  description = \"Example DNS zone\"",
										Highlighted: "\x1b[0m  \x1b[38;5;245mdescription\x1b[0m = \x1b[38;5;37m\"Example DNS zone\"",
									},
									{
										Number:      14,
										Content:     "",
										Highlighted: "\x1b[0m",
									},
									{
										Number:      15,
										Content:     "  dnssec_config {",
										Highlighted: "  dnssec_config {",
									},
									{
										Number:      16,
										Content:     "    state = local.dnssec_state[count.index]",
										IsCause:     true,
										Highlighted: "    \x1b[38;5;245mstate\x1b[0m = local.dnssec_state[\x1b[38;5;33mcount\x1b[0m.index]",
										FirstCause:  true,
										LastCause:   true,
									},
									{
										Number:      17,
										Content:     "  }",
										Highlighted: "  }",
									},
									{
										Number:      18,
										Content:     "}",
										Highlighted: "}",
									},
								},
							},
						},
					},
				},
			},
			opts: []table.MisconfRendererOption{
				table.WithGroupingResults(true),
				table.WithIncludeNonFailures(true),
			},
			want: `
main.tf (terraform)
===================
Tests: 3 (SUCCESSES: 1, FAILURES: 2, EXCEPTIONS: 0)
Failures: 2 (LOW: 0, MEDIUM: 2, HIGH: 0, CRITICAL: 0)

FAIL: MEDIUM: Managed zone does not have DNSSEC enabled. (1 similar result)
════════════════════════════════════════
DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.

See https://avd.aquasec.com/misconfig/avd-gcp-0013
────────────────────────────────────────
 main.tf:16
   via main.tf:15-17 (dnssec_config)
    via main.tf:9-18 (google_dns_managed_zone.this[0])
────────────────────────────────────────
   9   resource "google_dns_managed_zone" "this" {
  10     count       = 3
  11     name        = "example-zone-${count.index}"
  12     dns_name    = "example-${random_id.dns.hex}.com."
  13     description = "Example DNS zone"
  14   
  15     dnssec_config {
  16 [     state = local.dnssec_state[count.index]
  17     }
  18   }
────────────────────────────────────────
The rest causes:
 - main.tf:16 (google_dns_managed_zone.this[0])
────────────────────────────────────────


PASS: MEDIUM: Managed zone does not have DNSSEC enabled.
════════════════════════════════════════
DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.

See https://avd.aquasec.com/misconfig/avd-gcp-0013
────────────────────────────────────────
 main.tf:16
   via main.tf:15-17 (dnssec_config)
    via main.tf:9-18 (google_dns_managed_zone.this[0])
────────────────────────────────────────
   9   resource "google_dns_managed_zone" "this" {
  10     count       = 3
  11     name        = "example-zone-${count.index}"
  12     dns_name    = "example-${random_id.dns.hex}.com."
  13     description = "Example DNS zone"
  14   
  15     dnssec_config {
  16 [     state = local.dnssec_state[count.index]
  17     }
  18   }
────────────────────────────────────────


`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			severities := []dbTypes.Severity{dbTypes.SeverityLow, dbTypes.SeverityMedium, dbTypes.SeverityHigh,
				dbTypes.SeverityCritical}
			renderer := table.NewMisconfigRenderer(test.input, severities, test.opts...)
			assert.Equal(t, test.want, strings.ReplaceAll(renderer.Render(), "\r\n", "\n"))
		})
	}
}
