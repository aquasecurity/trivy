package report_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReportWriter_Sarif(t *testing.T) {
	tests := []struct {
		name  string
		input types.Report
		want  *sarif.Report
	}{
		{
			name: "report with vulnerabilities",
			input: types.Report{
				ArtifactName: "debian:9",
				ArtifactType: artifact.TypeContainerImage,
				Metadata: types.Metadata{
					ImageID: "sha256:7640c3f9e75002deb419d5e32738eeff82cf2b3edca3781b4fe1f1f626d11b20",
					RepoTags: []string{
						"debian:9",
					},
					RepoDigests: []string{
						"debian@sha256:a8cc1744bbdd5266678e3e8b3e6387e45c053218438897e86876f2eb104e5534",
					},
				},
				Results: types.Results{
					{
						Target: "library/test 1",
						Class:  types.ClassOSPkg,
						Packages: []ftypes.Package{
							{
								Name:    "foo",
								Version: "1.2.3",
								Locations: []ftypes.Location{
									{
										StartLine: 5,
										EndLine:   10,
									},
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-0001",
								PkgName:          "foo",
								InstalledVersion: "1.2.3",
								FixedVersion:     "3.4.5",
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
								SeveritySource:   "redhat",
								Vulnerability: dbTypes.Vulnerability{
									Title:       "foobar",
									Description: "baz",
									Severity:    "HIGH",
									VendorSeverity: map[dbTypes.SourceID]dbTypes.Severity{
										vulnerability.NVD:    dbTypes.SeverityCritical,
										vulnerability.RedHat: dbTypes.SeverityHigh,
									},
									CVSS: map[dbTypes.SourceID]dbTypes.CVSS{
										vulnerability.NVD: {
											V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
											V3Score:  9.8,
										},
										vulnerability.RedHat: {
											V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
											V3Score:  7.5,
										},
									},
								},
							},
						},
					},
				},
			},
			want: &sarif.Report{
				Version: "2.1.0",
				Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				Runs: []*sarif.Run{
					{
						Tool: sarif.Tool{
							Driver: &sarif.ToolComponent{
								FullName:       lo.ToPtr("Trivy Vulnerability Scanner"),
								Name:           "Trivy",
								Version:        lo.ToPtr(""),
								InformationURI: lo.ToPtr("https://github.com/aquasecurity/trivy"),
								Rules: []*sarif.ReportingDescriptor{
									{
										ID:               "CVE-2020-0001",
										Name:             lo.ToPtr("OsPackageVulnerability"),
										ShortDescription: &sarif.MultiformatMessageString{Text: lo.ToPtr("foobar")},
										FullDescription:  &sarif.MultiformatMessageString{Text: lo.ToPtr("baz")},
										DefaultConfiguration: &sarif.ReportingConfiguration{
											Level: "error",
										},
										HelpURI: lo.ToPtr("https://avd.aquasec.com/nvd/cve-2020-0001"),
										Properties: map[string]any{
											"tags": []any{
												"vulnerability",
												"security",
												"HIGH",
											},
											"precision":         "very-high",
											"security-severity": "7.5",
										},
										Help: &sarif.MultiformatMessageString{
											Text:     lo.ToPtr("Vulnerability CVE-2020-0001\nSeverity: HIGH\nPackage: foo\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)\nbaz"),
											Markdown: lo.ToPtr("**Vulnerability CVE-2020-0001**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|foo|3.4.5|[CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)|\n\nbaz"),
										},
									},
								},
							},
						},
						Results: []*sarif.Result{
							{
								RuleID:    lo.ToPtr("CVE-2020-0001"),
								RuleIndex: lo.ToPtr[uint](0),
								Level:     lo.ToPtr("error"),
								Message:   sarif.Message{Text: lo.ToPtr("Package: foo\nInstalled Version: 1.2.3\nVulnerability CVE-2020-0001\nSeverity: HIGH\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)")},
								Locations: []*sarif.Location{
									{
										Message: &sarif.Message{Text: lo.ToPtr("library/test 1: foo@1.2.3")},
										PhysicalLocation: &sarif.PhysicalLocation{
											ArtifactLocation: &sarif.ArtifactLocation{
												URI:       lo.ToPtr("library/test%201"),
												URIBaseId: lo.ToPtr("ROOTPATH"),
											},
											Region: &sarif.Region{
												StartLine:   lo.ToPtr(5),
												EndLine:     lo.ToPtr(10),
												StartColumn: lo.ToPtr(1),
												EndColumn:   lo.ToPtr(1),
											},
										},
									},
									{
										Message: &sarif.Message{Text: lo.ToPtr("library/test 1: foo@1.2.3")},
										PhysicalLocation: &sarif.PhysicalLocation{
											ArtifactLocation: &sarif.ArtifactLocation{
												URI:       lo.ToPtr("library/test%201"),
												URIBaseId: lo.ToPtr("ROOTPATH"),
											},
											Region: &sarif.Region{
												StartLine:   lo.ToPtr(15),
												EndLine:     lo.ToPtr(20),
												StartColumn: lo.ToPtr(1),
												EndColumn:   lo.ToPtr(1),
											},
										},
									},
								},
							},
						},
						ColumnKind: "utf16CodeUnits",
						OriginalUriBaseIDs: map[string]*sarif.ArtifactLocation{
							"ROOTPATH": {
								URI: lo.ToPtr("file:///"),
							},
						},
						PropertyBag: sarif.PropertyBag{
							Properties: map[string]any{
								"imageName":   "debian:9",
								"imageID":     "sha256:7640c3f9e75002deb419d5e32738eeff82cf2b3edca3781b4fe1f1f626d11b20",
								"repoDigests": []any{"debian@sha256:a8cc1744bbdd5266678e3e8b3e6387e45c053218438897e86876f2eb104e5534"},
								"repoTags":    []any{"debian:9"},
							},
						},
					},
				},
			},
		},
		{
			name: "report with misconfigurations",
			input: types.Report{
				Results: types.Results{
					{
						Target: "library/test 1",
						Class:  types.ClassConfig,
						Misconfigurations: []types.DetectedMisconfiguration{
							{
								Type:       "Kubernetes Security Check",
								ID:         "KSV001",
								Title:      "Image tag ':latest' used",
								Message:    "Message",
								Severity:   "HIGH",
								PrimaryURL: "https://avd.aquasec.com/appshield/ksv001",
								Status:     types.MisconfStatusFailure,
							},
							{
								Type:       "Kubernetes Security Check",
								ID:         "KSV002",
								Title:      "SYS_ADMIN capability added",
								Message:    "Message",
								Severity:   "CRITICAL",
								PrimaryURL: "https://avd.aquasec.com/appshield/ksv002",
								Status:     types.MisconfStatusPassed,
							},
						},
					},
				},
			},
			want: &sarif.Report{
				Version: "2.1.0",
				Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				Runs: []*sarif.Run{
					{
						Tool: sarif.Tool{
							Driver: &sarif.ToolComponent{
								FullName:       lo.ToPtr("Trivy Vulnerability Scanner"),
								Name:           "Trivy",
								Version:        lo.ToPtr(""),
								InformationURI: lo.ToPtr("https://github.com/aquasecurity/trivy"),
								Rules: []*sarif.ReportingDescriptor{
									{
										ID:               "KSV001",
										Name:             lo.ToPtr("Misconfiguration"),
										ShortDescription: &sarif.MultiformatMessageString{Text: lo.ToPtr("Image tag &#39;:latest&#39; used")},
										FullDescription:  &sarif.MultiformatMessageString{Text: lo.ToPtr("")},
										DefaultConfiguration: &sarif.ReportingConfiguration{
											Level: "error",
										},
										HelpURI: lo.ToPtr("https://avd.aquasec.com/appshield/ksv001"),
										Properties: map[string]any{
											"tags": []any{
												"misconfiguration",
												"security",
												"HIGH",
											},
											"precision":         "very-high",
											"security-severity": "8.0",
										},
										Help: &sarif.MultiformatMessageString{
											Text:     lo.ToPtr("Misconfiguration KSV001\nType: Kubernetes Security Check\nSeverity: HIGH\nCheck: Image tag ':latest' used\nMessage: Message\nLink: [KSV001](https://avd.aquasec.com/appshield/ksv001)\n"),
											Markdown: lo.ToPtr("**Misconfiguration KSV001**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|Kubernetes Security Check|HIGH|Image tag ':latest' used|Message|[KSV001](https://avd.aquasec.com/appshield/ksv001)|\n\n"),
										},
									},
									{
										ID:               "KSV002",
										Name:             lo.ToPtr("Misconfiguration"),
										ShortDescription: &sarif.MultiformatMessageString{Text: lo.ToPtr("SYS_ADMIN capability added")},
										FullDescription:  &sarif.MultiformatMessageString{Text: lo.ToPtr("")},
										DefaultConfiguration: &sarif.ReportingConfiguration{
											Level: "error",
										},
										HelpURI: lo.ToPtr("https://avd.aquasec.com/appshield/ksv002"),
										Properties: map[string]any{
											"tags": []any{
												"misconfiguration",
												"security",
												"CRITICAL",
											},
											"precision":         "very-high",
											"security-severity": "9.5",
										},
										Help: &sarif.MultiformatMessageString{
											Text:     lo.ToPtr("Misconfiguration KSV002\nType: Kubernetes Security Check\nSeverity: CRITICAL\nCheck: SYS_ADMIN capability added\nMessage: Message\nLink: [KSV002](https://avd.aquasec.com/appshield/ksv002)\n"),
											Markdown: lo.ToPtr("**Misconfiguration KSV002**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|Kubernetes Security Check|CRITICAL|SYS_ADMIN capability added|Message|[KSV002](https://avd.aquasec.com/appshield/ksv002)|\n\n"),
										},
									},
								},
							},
						},
						Results: []*sarif.Result{
							{
								RuleID:    lo.ToPtr("KSV001"),
								RuleIndex: lo.ToPtr[uint](0),
								Level:     lo.ToPtr("error"),
								Message:   sarif.Message{Text: lo.ToPtr("Artifact: library/test 1\nType: \nVulnerability KSV001\nSeverity: HIGH\nMessage: Message\nLink: [KSV001](https://avd.aquasec.com/appshield/ksv001)")},
								Locations: []*sarif.Location{
									{
										Message: &sarif.Message{Text: lo.ToPtr("library/test 1")},
										PhysicalLocation: &sarif.PhysicalLocation{
											ArtifactLocation: &sarif.ArtifactLocation{
												URI:       lo.ToPtr("library/test%201"),
												URIBaseId: lo.ToPtr("ROOTPATH"),
											},
											Region: &sarif.Region{
												StartLine:   lo.ToPtr(1),
												EndLine:     lo.ToPtr(1),
												StartColumn: lo.ToPtr(1),
												EndColumn:   lo.ToPtr(1),
											},
										},
									},
								},
							},
							{
								RuleID:    lo.ToPtr("KSV002"),
								RuleIndex: lo.ToPtr[uint](1),
								Level:     lo.ToPtr("error"),
								Message:   sarif.Message{Text: lo.ToPtr("Artifact: library/test 1\nType: \nVulnerability KSV002\nSeverity: CRITICAL\nMessage: Message\nLink: [KSV002](https://avd.aquasec.com/appshield/ksv002)")},
								Locations: []*sarif.Location{
									{
										Message: &sarif.Message{Text: lo.ToPtr("library/test 1")},
										PhysicalLocation: &sarif.PhysicalLocation{
											ArtifactLocation: &sarif.ArtifactLocation{
												URI:       lo.ToPtr("library/test%201"),
												URIBaseId: lo.ToPtr("ROOTPATH"),
											},
											Region: &sarif.Region{
												StartLine:   lo.ToPtr(1),
												EndLine:     lo.ToPtr(1),
												StartColumn: lo.ToPtr(1),
												EndColumn:   lo.ToPtr(1),
											},
										},
									},
								},
							},
						},
						ColumnKind: "utf16CodeUnits",
						OriginalUriBaseIDs: map[string]*sarif.ArtifactLocation{
							"ROOTPATH": {
								URI: lo.ToPtr("file:///"),
							},
						},
					},
				},
			},
		},
		{
			name: "report with secrets",
			input: types.Report{
				Results: types.Results{
					{
						Target: "library/test 1",
						Class:  types.ClassSecret,
						Secrets: []types.DetectedSecret{
							{
								RuleID:    "aws-secret-access-key",
								Category:  "AWS",
								Severity:  "CRITICAL",
								Title:     "AWS Secret Access Key",
								StartLine: 1,
								EndLine:   1,
								Match:     "'AWS_secret_KEY'=\"****************************************\"",
							},
						},
					},
				},
			},
			want: &sarif.Report{
				Version: "2.1.0",
				Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				Runs: []*sarif.Run{
					{
						Tool: sarif.Tool{
							Driver: &sarif.ToolComponent{
								FullName:       lo.ToPtr("Trivy Vulnerability Scanner"),
								Name:           "Trivy",
								Version:        lo.ToPtr(""),
								InformationURI: lo.ToPtr("https://github.com/aquasecurity/trivy"),
								Rules: []*sarif.ReportingDescriptor{
									{
										ID:               "aws-secret-access-key",
										Name:             lo.ToPtr("Secret"),
										ShortDescription: &sarif.MultiformatMessageString{Text: lo.ToPtr("AWS Secret Access Key")},
										FullDescription:  &sarif.MultiformatMessageString{Text: lo.ToPtr("\u0026#39;AWS_secret_KEY\u0026#39;=\u0026#34;****************************************\u0026#34;")},
										DefaultConfiguration: &sarif.ReportingConfiguration{
											Level: "error",
										},
										HelpURI: lo.ToPtr("https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/secret/builtin-rules.go"),
										Properties: map[string]any{
											"tags": []any{
												"secret",
												"security",
												"CRITICAL",
											},
											"precision":         "very-high",
											"security-severity": "9.5",
										},
										Help: &sarif.MultiformatMessageString{
											Text:     lo.ToPtr("Secret AWS Secret Access Key\nSeverity: CRITICAL\nMatch: 'AWS_secret_KEY'=\"****************************************\""),
											Markdown: lo.ToPtr("**Secret AWS Secret Access Key**\n| Severity | Match |\n| --- | --- |\n|CRITICAL|'AWS_secret_KEY'=\"****************************************\"|"),
										},
									},
								},
							},
						},
						Results: []*sarif.Result{
							{
								RuleID:    lo.ToPtr("aws-secret-access-key"),
								RuleIndex: lo.ToPtr[uint](0),
								Level:     lo.ToPtr("error"),
								Message:   sarif.Message{Text: lo.ToPtr("Artifact: library/test 1\nType: \nSecret AWS Secret Access Key\nSeverity: CRITICAL\nMatch: 'AWS_secret_KEY'=\"****************************************\"")},
								Locations: []*sarif.Location{
									{
										Message: &sarif.Message{Text: lo.ToPtr("library/test 1")},
										PhysicalLocation: &sarif.PhysicalLocation{
											ArtifactLocation: &sarif.ArtifactLocation{
												URI:       lo.ToPtr("library/test%201"),
												URIBaseId: lo.ToPtr("ROOTPATH"),
											},
											Region: &sarif.Region{
												StartLine:   lo.ToPtr(1),
												EndLine:     lo.ToPtr(1),
												StartColumn: lo.ToPtr(1),
												EndColumn:   lo.ToPtr(1),
											},
										},
									},
								},
							},
						},
						ColumnKind: "utf16CodeUnits",
						OriginalUriBaseIDs: map[string]*sarif.ArtifactLocation{
							"ROOTPATH": {
								URI: lo.ToPtr("file:///"),
							},
						},
					},
				},
			},
		},
		{
			name: "report with licenses",
			input: types.Report{
				Results: types.Results{
					{
						Target: "OS Packages",
						Class:  "license",
						Licenses: []types.DetectedLicense{
							{
								Severity:   "HIGH",
								Category:   "restricted",
								PkgName:    "alpine-base",
								FilePath:   "",
								Name:       "GPL-3.0",
								Confidence: 1,
								Link:       "",
							},
						},
					},
				},
			},
			want: &sarif.Report{
				Version: "2.1.0",
				Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				Runs: []*sarif.Run{
					{
						Tool: sarif.Tool{
							Driver: &sarif.ToolComponent{
								FullName:       lo.ToPtr("Trivy Vulnerability Scanner"),
								Name:           "Trivy",
								Version:        lo.ToPtr(""),
								InformationURI: lo.ToPtr("https://github.com/aquasecurity/trivy"),
								Rules: []*sarif.ReportingDescriptor{
									{
										ID:                   "alpine-base:GPL-3.0",
										Name:                 lo.ToPtr("License"),
										ShortDescription:     sarif.NewMultiformatMessageString("GPL-3.0 in alpine-base"),
										FullDescription:      sarif.NewMultiformatMessageString("GPL-3.0 in alpine-base"),
										DefaultConfiguration: sarif.NewReportingConfiguration().WithLevel("error"),
										Help: sarif.NewMultiformatMessageString("License GPL-3.0\nClassification: restricted\nPkgName: alpine-base\nPath: ").
											WithMarkdown("**License GPL-3.0**\n| PkgName | Classification | Path |\n| --- | --- | --- |\n|alpine-base|restricted||"),
										Properties: map[string]any{
											"tags": []any{
												"license",
												"security",
												"HIGH",
											},
											"precision":         "very-high",
											"security-severity": "8.0",
										},
									},
								},
							},
						},
						Results: []*sarif.Result{
							{
								RuleID:    lo.ToPtr("alpine-base:GPL-3.0"),
								RuleIndex: lo.ToPtr(uint(0)),
								Level:     lo.ToPtr("error"),
								Message:   sarif.Message{Text: lo.ToPtr("Artifact: OS Packages\nLicense GPL-3.0\nPkgName: restricted\n Classification: alpine-base\n Path: ")},
								Locations: []*sarif.Location{
									{
										Message: sarif.NewTextMessage(""),
										PhysicalLocation: &sarif.PhysicalLocation{
											ArtifactLocation: &sarif.ArtifactLocation{
												URI:       lo.ToPtr("OS%20Packages"),
												URIBaseId: lo.ToPtr("ROOTPATH"),
											},
											Region: &sarif.Region{
												StartLine:   lo.ToPtr(1),
												EndLine:     lo.ToPtr(1),
												StartColumn: lo.ToPtr(1),
												EndColumn:   lo.ToPtr(1),
											},
										},
									},
								},
							},
						},
						ColumnKind: "utf16CodeUnits",
						OriginalUriBaseIDs: map[string]*sarif.ArtifactLocation{
							"ROOTPATH": {
								URI: lo.ToPtr("file:///"),
							},
						},
					},
				},
			},
		},
		{
			name: "no vulns",
			want: &sarif.Report{
				Version: "2.1.0",
				Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				Runs: []*sarif.Run{
					{
						Tool: sarif.Tool{
							Driver: &sarif.ToolComponent{
								FullName:       lo.ToPtr("Trivy Vulnerability Scanner"),
								Name:           "Trivy",
								Version:        lo.ToPtr(""),
								InformationURI: lo.ToPtr("https://github.com/aquasecurity/trivy"),
								Rules:          []*sarif.ReportingDescriptor{},
							},
						},
						Results:    []*sarif.Result{},
						ColumnKind: "utf16CodeUnits",
						OriginalUriBaseIDs: map[string]*sarif.ArtifactLocation{
							"ROOTPATH": {
								URI: lo.ToPtr("file:///"),
							},
						},
					},
				},
			},
		},
		{
			name: "ref to github",
			input: types.Report{
				Results: types.Results{
					{
						Target: "git::https:/github.com/terraform-google-modules/terraform-google-kubernetes-engine?ref=c4809044b52b91505bfba5ef9f25526aa0361788/modules/workload-identity/main.tf",
						Class:  types.ClassConfig,
						Type:   ftypes.Terraform,
						Misconfigurations: []types.DetectedMisconfiguration{
							{
								Type:        "Terraform Security Check",
								ID:          "AVD-GCP-0007",
								AVDID:       "AVD-GCP-0007",
								Title:       "Service accounts should not have roles assigned with excessive privileges",
								Description: "Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.",
								Message:     "Service account is granted a privileged role.",
								Query:       "data..",
								Resolution:  "Limit service account access to minimal required set",
								Severity:    "HIGH",
								PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-gcp-0007",
								References: []string{
									"https://cloud.google.com/iam/docs/understanding-roles",
									"https://avd.aquasec.com/misconfig/avd-gcp-0007",
								},
								Status: "Fail",
								CauseMetadata: ftypes.CauseMetadata{
									StartLine: 91,
									EndLine:   91,
									Occurrences: []ftypes.Occurrence{
										{
											Resource: "google_project_iam_member.workload_identity_sa_bindings[\"roles/storage.admin\"]",
											Filename: "git::https:/github.com/terraform-google-modules/terraform-google-kubernetes-engine?ref=c4809044b52b91505bfba5ef9f25526aa0361788/modules/workload-identity/main.tf",
											Location: ftypes.Location{
												StartLine: 87,
												EndLine:   93,
											},
										},
									},
								},
							},
						},
					},
					{
						Target: "git@github.com:terraform-aws-modules/terraform-aws-s3-bucket.git?ref=v4.2.0/main.tf",
						Class:  types.ClassConfig,
						Type:   ftypes.Terraform,
						Misconfigurations: []types.DetectedMisconfiguration{
							{
								Type:        "Terraform Security Check",
								ID:          "AVD-GCP-0007",
								AVDID:       "AVD-GCP-0007",
								Title:       "Service accounts should not have roles assigned with excessive privileges",
								Description: "Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.",
								Message:     "Service account is granted a privileged role.",
								Query:       "data..",
								Resolution:  "Limit service account access to minimal required set",
								Severity:    "HIGH",
								PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-gcp-0007",
								References: []string{
									"https://cloud.google.com/iam/docs/understanding-roles",
									"https://avd.aquasec.com/misconfig/avd-gcp-0007",
								},
								Status: "Fail",
								CauseMetadata: ftypes.CauseMetadata{
									StartLine: 91,
									EndLine:   91,
									Occurrences: []ftypes.Occurrence{
										{
											Resource: "google_project_iam_member.workload_identity_sa_bindings[\"roles/storage.admin\"]",
											Filename: "git@github.com:terraform-aws-modules/terraform-aws-s3-bucket.git?ref=v4.2.0/main.tf",
											Location: ftypes.Location{
												StartLine: 87,
												EndLine:   93,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: &sarif.Report{
				Version: "2.1.0",
				Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				Runs: []*sarif.Run{
					{
						Tool: *sarif.NewTool(
							&sarif.ToolComponent{
								FullName:       lo.ToPtr("Trivy Vulnerability Scanner"),
								Name:           "Trivy",
								Version:        lo.ToPtr(""),
								InformationURI: lo.ToPtr("https://github.com/aquasecurity/trivy"),
								Rules: []*sarif.ReportingDescriptor{
									{
										ID:               "AVD-GCP-0007",
										Name:             lo.ToPtr("Misconfiguration"),
										ShortDescription: sarif.NewMultiformatMessageString("Service accounts should not have roles assigned with excessive privileges"),
										FullDescription:  sarif.NewMultiformatMessageString("Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account."),
										DefaultConfiguration: &sarif.ReportingConfiguration{
											Level: "error",
										},
										HelpURI: lo.ToPtr("https://avd.aquasec.com/misconfig/avd-gcp-0007"),
										Help: &sarif.MultiformatMessageString{
											Text:     lo.ToPtr("Misconfiguration AVD-GCP-0007\nType: Terraform Security Check\nSeverity: HIGH\nCheck: Service accounts should not have roles assigned with excessive privileges\nMessage: Service account is granted a privileged role.\nLink: [AVD-GCP-0007](https://avd.aquasec.com/misconfig/avd-gcp-0007)\nService accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account."),
											Markdown: lo.ToPtr("**Misconfiguration AVD-GCP-0007**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|Terraform Security Check|HIGH|Service accounts should not have roles assigned with excessive privileges|Service account is granted a privileged role.|[AVD-GCP-0007](https://avd.aquasec.com/misconfig/avd-gcp-0007)|\n\nService accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account."),
										},
										Properties: sarif.Properties{
											"tags": []any{
												"misconfiguration",
												"security",
												"HIGH",
											},
											"precision":         "very-high",
											"security-severity": "8.0",
										},
									},
								},
							},
						),
						Results: []*sarif.Result{
							{
								RuleID:    lo.ToPtr("AVD-GCP-0007"),
								RuleIndex: lo.ToPtr(uint(0)),
								Level:     lo.ToPtr("error"),
								Message:   *sarif.NewTextMessage("Artifact: github.com/terraform-google-modules/terraform-google-kubernetes-engine?ref=c4809044b52b91505bfba5ef9f25526aa0361788/modules/workload-identity/main.tf\nType: terraform\nVulnerability AVD-GCP-0007\nSeverity: HIGH\nMessage: Service account is granted a privileged role.\nLink: [AVD-GCP-0007](https://avd.aquasec.com/misconfig/avd-gcp-0007)"),
								Locations: []*sarif.Location{
									{
										PhysicalLocation: sarif.NewPhysicalLocation().
											WithArtifactLocation(
												&sarif.ArtifactLocation{
													URI:       lo.ToPtr("github.com/terraform-google-modules/terraform-google-kubernetes-engine?ref=c4809044b52b91505bfba5ef9f25526aa0361788/modules/workload-identity/main.tf"),
													URIBaseId: lo.ToPtr("ROOTPATH"),
												},
											).
											WithRegion(
												&sarif.Region{
													StartLine:   lo.ToPtr(91),
													StartColumn: lo.ToPtr(1),
													EndLine:     lo.ToPtr(91),
													EndColumn:   lo.ToPtr(1),
												},
											),
										Message: sarif.NewTextMessage("github.com/terraform-google-modules/terraform-google-kubernetes-engine?ref=c4809044b52b91505bfba5ef9f25526aa0361788/modules/workload-identity/main.tf"),
									},
								},
							},
							{
								RuleID:    lo.ToPtr("AVD-GCP-0007"),
								RuleIndex: lo.ToPtr(uint(0)),
								Level:     lo.ToPtr("error"),
								Message:   *sarif.NewTextMessage("Artifact: github.com/terraform-aws-modules/terraform-aws-s3-bucket/tree/v4.2.0/main.tf\nType: terraform\nVulnerability AVD-GCP-0007\nSeverity: HIGH\nMessage: Service account is granted a privileged role.\nLink: [AVD-GCP-0007](https://avd.aquasec.com/misconfig/avd-gcp-0007)"),
								Locations: []*sarif.Location{
									{
										PhysicalLocation: sarif.NewPhysicalLocation().
											WithArtifactLocation(
												&sarif.ArtifactLocation{
													URI:       lo.ToPtr("github.com/terraform-aws-modules/terraform-aws-s3-bucket/tree/v4.2.0/main.tf"),
													URIBaseId: lo.ToPtr("ROOTPATH"),
												},
											).
											WithRegion(
												&sarif.Region{
													StartLine:   lo.ToPtr(91),
													StartColumn: lo.ToPtr(1),
													EndLine:     lo.ToPtr(91),
													EndColumn:   lo.ToPtr(1),
												},
											),
										Message: sarif.NewTextMessage("github.com/terraform-aws-modules/terraform-aws-s3-bucket/tree/v4.2.0/main.tf"),
									},
								},
							},
						},
						ColumnKind: "utf16CodeUnits",
						OriginalUriBaseIDs: map[string]*sarif.ArtifactLocation{
							"ROOTPATH": {
								URI: lo.ToPtr("file:///"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sarifWritten := bytes.NewBuffer(nil)
			w := report.SarifWriter{
				Output: sarifWritten,
			}
			err := w.Write(context.TODO(), tt.input)
			require.NoError(t, err)

			result := &sarif.Report{}
			err = json.Unmarshal(sarifWritten.Bytes(), result)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestToPathUri(t *testing.T) {
	tests := []struct {
		input       string
		resultClass types.ResultClass
		output      string
	}{
		{
			input:       "almalinux@sha256:08042694fffd61e6a0b3a22dadba207c8937977915ff6b1879ad744fd6638837",
			resultClass: types.ClassOSPkg,
			output:      "library/almalinux",
		},
		{
			input:       "alpine:latest (alpine 3.13.4)",
			resultClass: types.ClassOSPkg,
			output:      "library/alpine",
		},
		{
			input:       "docker.io/my-organization/my-app:2c6912aee7bde44b84d810aed106ca84f40e2e29",
			resultClass: types.ClassOSPkg,
			output:      "my-organization/my-app",
		},
		{
			input:       "lib/test",
			resultClass: types.ClassLangPkg,
			output:      "lib/test",
		},
		{
			input:       "lib(2)/test",
			resultClass: types.ClassSecret,
			output:      "lib(2)/test",
		},
	}

	for _, test := range tests {
		got := report.ToPathUri(test.input, test.resultClass)
		if got != test.output {
			t.Errorf("toPathUri(%q) got %q, wanted %q", test.input, got, test.output)
		}
	}
}
