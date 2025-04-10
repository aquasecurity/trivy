package report

import (
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestSeparateMisconfigReports_NoDuplicates(t *testing.T) {
	tests := []struct {
		name     string
		report   Report
		scanners types.Scanners
		want     []reports
	}{
		{
			name: "Resource with both vulnerabilities and misconfigurations",
			report: Report{
				Resources: []Resource{
					{
						Namespace: "default",
						Kind:      "Deployment",
						Name:      "app",
						Results: types.Results{
							{
								Vulnerabilities: []types.DetectedVulnerability{
									{
										VulnerabilityID: "CVE-2020-1234",
										PkgName:         "test-pkg",
										Vulnerability: dbTypes.Vulnerability{
											Severity: dbTypes.SeverityHigh.String(),
										},
									},
								},
							},
						},
					},
					{
						Namespace: "default",
						Kind:      "Deployment",
						Name:      "app",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{
										ID:       "MC-001",
										Severity: dbTypes.SeverityMedium.String(),
									},
								},
							},
						},
					},
				},
			},
			scanners: types.Scanners{types.VulnerabilityScanner, types.MisconfigScanner},
			want: []reports{
				{
					Report: Report{
						Resources: []Resource{
							{
								Namespace: "default",
								Kind:      "Deployment",
								Name:      "app",
								Results: types.Results{
									{
										Vulnerabilities: []types.DetectedVulnerability{
											{
												VulnerabilityID: "CVE-2020-1234",
												PkgName:         "test-pkg",
												Vulnerability: dbTypes.Vulnerability{
													Severity: dbTypes.SeverityHigh.String(),
												},
											},
										},
										Misconfigurations: []types.DetectedMisconfiguration{
											{
												ID:       "MC-001",
												Severity: dbTypes.SeverityMedium.String(),
											},
										},
									},
								},
							},
						},
						name: "Workload Assessment",
					},
					Columns: []string{
						VulnerabilitiesColumn,
						MisconfigurationsColumn,
						SecretsColumn,
					},
				},
			},
		},
		{
			name: "Node with both vulnerabilities and misconfigurations",
			report: Report{
				Resources: []Resource{
					{
						Namespace: "kube-system",
						Kind:      "NodeComponents",
						Name:      "node1",
						Results: types.Results{
							{
								Vulnerabilities: []types.DetectedVulnerability{
									{
										VulnerabilityID: "CVE-2020-5678",
										PkgName:         "os-pkg",
										Vulnerability: dbTypes.Vulnerability{
											Severity: dbTypes.SeverityCritical.String(),
										},
									},
								},
							},
						},
					},
					{
						Namespace: "kube-system",
						Kind:      "NodeComponents",
						Name:      "node1",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{
										ID:       "MC-002",
										Severity: dbTypes.SeverityHigh.String(),
									},
								},
							},
						},
					},
				},
			},
			scanners: types.Scanners{types.VulnerabilityScanner, types.MisconfigScanner},
			want: []reports{
				{
					Report: Report{
						Resources: []Resource{
							{
								Kind: "Node",
								Name: "node1",
								Results: types.Results{
									{
										Vulnerabilities: []types.DetectedVulnerability{
											{
												VulnerabilityID: "CVE-2020-5678",
												PkgName:         "os-pkg",
												Vulnerability: dbTypes.Vulnerability{
													Severity: dbTypes.SeverityCritical.String(),
												},
											},
										},
										Misconfigurations: []types.DetectedMisconfiguration{
											{
												ID:       "MC-002",
												Severity: dbTypes.SeverityHigh.String(),
											},
										},
									},
								},
							},
						},
						name: "Infra Assessment",
					},
					Columns: []string{
						VulnerabilitiesColumn,
						MisconfigurationsColumn,
						SecretsColumn,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SeparateMisconfigReports(tt.report, tt.scanners)

			// For each report in the result
			for i, report := range got {
				// Check if we have expected report for this index
				if i >= len(tt.want) {
					t.Errorf("Got more reports than expected. Extra report at index %d", i)
					continue
				}

				// Check report names match
				assert.Equal(t, tt.want[i].Report.name, report.Report.name)

				// Check columns match
				assert.Equal(t, tt.want[i].Columns, report.Columns)

				// Check resources length matches
				assert.Equal(t, len(tt.want[i].Report.Resources), len(report.Report.Resources))

				// For each resource in the report
				for j, resource := range report.Report.Resources {
					// Verify no duplicate entries for the same resource
					assert.Equal(t, tt.want[i].Report.Resources[j].Namespace, resource.Namespace)
					assert.Equal(t, tt.want[i].Report.Resources[j].Kind, resource.Kind)
					assert.Equal(t, tt.want[i].Report.Resources[j].Name, resource.Name)

					// Verify all findings are preserved
					assert.Equal(t,
						len(tt.want[i].Report.Resources[j].Results[0].Vulnerabilities),
						len(resource.Results[0].Vulnerabilities),
					)
					assert.Equal(t,
						len(tt.want[i].Report.Resources[j].Results[0].Misconfigurations),
						len(resource.Results[0].Misconfigurations),
					)
				}
			}
		})
	}
}
