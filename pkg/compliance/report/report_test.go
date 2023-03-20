package report_test

import (
	"fmt"
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestBuildComplianceReport(t *testing.T) {
	type args struct {
		scanResults []types.Results
		cs          spec.ComplianceSpec
	}
	tests := []struct {
		name    string
		args    args
		want    *report.ComplianceReport
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "happy",
			args: args{
				scanResults: []types.Results{
					{
						{
							Target: "Deployment/metrics-server",
							Class:  types.ClassConfig,
							Type:   ftypes.Kubernetes,
							MisconfSummary: &types.MisconfSummary{
								Successes:  1,
								Failures:   0,
								Exceptions: 0,
							},
							Misconfigurations: []types.DetectedMisconfiguration{
								{
									Type:        "Kubernetes Security Check",
									ID:          "KSV001",
									AVDID:       "AVD-KSV-0001",
									Title:       "Process can elevate its own privileges",
									Description: "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
									Message:     "Container 'metrics-server' of Deployment 'metrics-server' should set 'securityContext.allowPrivilegeEscalation' to false",
									Namespace:   "builtin.kubernetes.KSV001",
									Query:       "data.builtin.kubernetes.KSV001.deny",
									Resolution:  "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.",
									Severity:    dbTypes.SeverityMedium.String(),
									PrimaryURL:  "https://avd.aquasec.com/misconfig/ksv001",
									References: []string{
										"https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
										"https://avd.aquasec.com/misconfig/ksv001",
									},
									Status: types.StatusPassed,
								},
								{
									Type:   "Kubernetes Security Check",
									ID:     "KSV002",
									AVDID:  "AVD-KSV-9999",
									Status: types.StatusFailure,
								},
							},
						},
					},
					{
						{
							Target: "rancher/metrics-server:v0.3.6 (debian 9.9)",
							Class:  types.ClassOSPkg,
							Type:   "debian",
							Vulnerabilities: []types.DetectedVulnerability{
								{
									VulnerabilityID:  "DLA-2424-1",
									VendorIDs:        []string{"DLA-2424-1"},
									PkgName:          "tzdata",
									InstalledVersion: "2019a-0+deb9u1",
									FixedVersion:     "2020d-0+deb9u1",
									Layer: ftypes.Layer{
										DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
									},
									DataSource: &dbTypes.DataSource{
										ID:   vulnerability.Debian,
										Name: "Debian Security Tracker",
										URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
									},
									Vulnerability: dbTypes.Vulnerability{
										Title:    "tzdata - new upstream version",
										Severity: dbTypes.SeverityUnknown.String(),
									},
								},
							},
						},
					},
				},
				cs: spec.ComplianceSpec{
					Spec: defsecTypes.Spec{
						ID:          "1234",
						Title:       "NSA",
						Description: "National Security Agency - Kubernetes Hardening Guidance",
						Version:     "1.0",
						RelatedResources: []string{
							"https://example.com",
						},
						Controls: []defsecTypes.Control{
							{
								ID:          "1.0",
								Name:        "Non-root containers",
								Description: "Check that container is not running as root",
								Severity:    "MEDIUM",
								Checks: []defsecTypes.SpecCheck{
									{ID: "AVD-KSV-0001"},
								},
							},
							{
								ID:          "1.1",
								Name:        "Immutable container file systems",
								Description: "Check that container root file system is immutable",
								Severity:    "LOW",
								Checks: []defsecTypes.SpecCheck{
									{ID: "AVD-KSV-0002"},
								},
							},
							{
								ID:          "1.2",
								Name:        "tzdata - new upstream version",
								Description: "Bad tzdata package",
								Severity:    "CRITICAL",
								Checks: []defsecTypes.SpecCheck{
									{ID: "DLA-2424-1"},
								},
							},
						},
					},
				},
			},
			want: &report.ComplianceReport{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				Version:     "1.0",
				RelatedResources: []string{
					"https://example.com",
				},
				Results: []*report.ControlCheckResult{
					{
						ID:          "1.0",
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						Severity:    "MEDIUM",
						Results: types.Results{
							{
								Target: "Deployment/metrics-server",
								Class:  types.ClassConfig,
								Type:   ftypes.Kubernetes,
								MisconfSummary: &types.MisconfSummary{
									Successes:  1,
									Failures:   0,
									Exceptions: 0,
								},
								Misconfigurations: []types.DetectedMisconfiguration{
									{
										Type:        "Kubernetes Security Check",
										ID:          "KSV001",
										AVDID:       "AVD-KSV-0001",
										Title:       "Process can elevate its own privileges",
										Description: "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
										Message:     "Container 'metrics-server' of Deployment 'metrics-server' should set 'securityContext.allowPrivilegeEscalation' to false",
										Namespace:   "builtin.kubernetes.KSV001",
										Query:       "data.builtin.kubernetes.KSV001.deny",
										Resolution:  "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.",
										Severity:    dbTypes.SeverityMedium.String(),
										PrimaryURL:  "https://avd.aquasec.com/misconfig/ksv001",
										References: []string{
											"https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
											"https://avd.aquasec.com/misconfig/ksv001",
										},
										Status: types.StatusPassed,
									},
								},
							},
						},
					},
					{
						ID:          "1.1",
						Name:        "Immutable container file systems",
						Description: "Check that container root file system is immutable",
						Severity:    "LOW",
						Results:     nil,
					},
					{
						ID:          "1.2",
						Name:        "tzdata - new upstream version",
						Description: "Bad tzdata package",
						Severity:    "CRITICAL",
						Results: types.Results{
							{
								Target: "rancher/metrics-server:v0.3.6 (debian 9.9)",
								Class:  types.ClassOSPkg,
								Type:   "debian",
								Vulnerabilities: []types.DetectedVulnerability{
									{
										VulnerabilityID:  "DLA-2424-1",
										VendorIDs:        []string{"DLA-2424-1"},
										PkgName:          "tzdata",
										InstalledVersion: "2019a-0+deb9u1",
										FixedVersion:     "2020d-0+deb9u1",
										Layer: ftypes.Layer{
											DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
										},
										DataSource: &dbTypes.DataSource{
											ID:   vulnerability.Debian,
											Name: "Debian Security Tracker",
											URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
										},
										Vulnerability: dbTypes.Vulnerability{
											Title:    "tzdata - new upstream version",
											Severity: dbTypes.SeverityUnknown.String(),
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := report.BuildComplianceReport(tt.args.scanResults, tt.args.cs)
			if !tt.wantErr(t, err, fmt.Sprintf("BuildComplianceReport(%v, %v)", tt.args.scanResults, tt.args.cs)) {
				return
			}
			assert.Equalf(t, tt.want, got, "BuildComplianceReport(%v, %v)", tt.args.scanResults, tt.args.cs)
		})
	}
}
