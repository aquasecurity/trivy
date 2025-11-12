package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestFill(t *testing.T) {
	tests := []struct {
		name       string
		report     *types.Report
		wantReport *types.Report
	}{
		{
			name: "single vulnerability",
			report: &types.Report{
				ArtifactID: "sha256:abc123",
				Results: []types.Result{
					{
						Target: "app/package.json",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgID:           "lodash@4.17.0",
								VulnerabilityID: "CVE-2021-1234",
							},
						},
					},
				},
			},
			wantReport: &types.Report{
				ArtifactID: "sha256:abc123",
				Results: []types.Result{
					{
						Target: "app/package.json",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgID:           "lodash@4.17.0",
								VulnerabilityID: "CVE-2021-1234",
								Fingerprint:     "sha256:7bf63097f9e930e203cfcb74b3ae9cf51c52cc016fa81da297a4d695dadd728f", // hash(sha256:abc123:app/package.json:lodash@4.17.0:CVE-2021-1234)
							},
						},
					},
				},
			},
		},
		{
			name: "multiple vulnerabilities in multiple results",
			report: &types.Report{
				ArtifactID: "sha256:def456",
				Results: []types.Result{
					{
						Target: "app1/package.json",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgID:           "express@4.17.0",
								VulnerabilityID: "CVE-2021-5678",
							},
							{
								PkgID:           "lodash@4.17.0",
								VulnerabilityID: "CVE-2021-1234",
							},
						},
					},
					{
						Target: "app2/package.json",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgID:           "lodash@4.17.0",
								VulnerabilityID: "CVE-2021-1234",
							},
						},
					},
				},
			},
			wantReport: &types.Report{
				ArtifactID: "sha256:def456",
				Results: []types.Result{
					{
						Target: "app1/package.json",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgID:           "express@4.17.0",
								VulnerabilityID: "CVE-2021-5678",
								Fingerprint:     "sha256:6666c513c31c1155541e73f806edccb717773e0839d2631e8758de34ed4bf9f7", // hash(sha256:def456:app1/package.json:express@4.17.0:CVE-2021-5678)
							},
							{
								PkgID:           "lodash@4.17.0",
								VulnerabilityID: "CVE-2021-1234",
								Fingerprint:     "sha256:c4d943760ae3cd4b8782bff29a44f67823b7579bae83e2abce1fdd2f11516527", // hash(sha256:def456:app1/package.json:lodash@4.17.0:CVE-2021-1234)
							},
						},
					},
					{
						Target: "app2/package.json",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgID:           "lodash@4.17.0",
								VulnerabilityID: "CVE-2021-1234",
								Fingerprint:     "sha256:1e0a807019aeeecabf004de2bb1bf22646752e7905be5a742377f4760d852520", // hash(sha256:def456:app2/package.json:lodash@4.17.0:CVE-2021-1234)
							},
						},
					},
				},
			},
		},
		{
			name: "empty report",
			report: &types.Report{
				ArtifactID: "sha256:empty",
				Results:    []types.Result{},
			},
			wantReport: &types.Report{
				ArtifactID: "sha256:empty",
				Results:    []types.Result{},
			},
		},
		{
			name: "result without vulnerabilities",
			report: &types.Report{
				ArtifactID: "sha256:novulns",
				Results: []types.Result{
					{
						Target:          "app/package.json",
						Vulnerabilities: []types.DetectedVulnerability{},
					},
				},
			},
			wantReport: &types.Report{
				ArtifactID: "sha256:novulns",
				Results: []types.Result{
					{
						Target:          "app/package.json",
						Vulnerabilities: []types.DetectedVulnerability{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Fill(tt.report)

			// Verify the entire report matches expected
			assert.Equal(t, tt.wantReport, tt.report)
		})
	}
}

func Test_fillVulnerabilities(t *testing.T) {
	tests := []struct {
		name       string
		artifactID string
		target     string
		vulns      []types.DetectedVulnerability
		wantVulns  []types.DetectedVulnerability
	}{
		{
			name:       "multiple vulnerabilities with unique fingerprints",
			artifactID: "sha256:test123",
			target:     "test-target",
			vulns: []types.DetectedVulnerability{
				{
					PkgID:           "pkg1@1.0.0",
					VulnerabilityID: "CVE-2021-0001",
				},
				{
					PkgID:           "pkg2@2.0.0",
					VulnerabilityID: "CVE-2021-0002",
				},
				{
					PkgID:           "pkg3@3.0.0",
					VulnerabilityID: "CVE-2021-0003",
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					PkgID:           "pkg1@1.0.0",
					VulnerabilityID: "CVE-2021-0001",
					Fingerprint:     "sha256:099e52439185c144012d07bff4d3e6a840b6d0366c175da12308fd7e82c49f4b", // hash(sha256:test123:test-target:pkg1@1.0.0:CVE-2021-0001)
				},
				{
					PkgID:           "pkg2@2.0.0",
					VulnerabilityID: "CVE-2021-0002",
					Fingerprint:     "sha256:7afdba1b87fb21abfac82517a4fbaf6a472761af1c2376405580040da998e3b9", // hash(sha256:test123:test-target:pkg2@2.0.0:CVE-2021-0002)
				},
				{
					PkgID:           "pkg3@3.0.0",
					VulnerabilityID: "CVE-2021-0003",
					Fingerprint:     "sha256:0eea75192d06f745c4a22e85159747984dd6f6014aeb5e341f4108b2bd12db18", // hash(sha256:test123:test-target:pkg3@3.0.0:CVE-2021-0003)
				},
			},
		},
		{
			name:       "same vulnerability in different targets produces different fingerprints",
			artifactID: "sha256:abc",
			target:     "app1/package.json",
			vulns: []types.DetectedVulnerability{
				{
					PkgID:           "lodash@4.17.0",
					VulnerabilityID: "CVE-2021-1234",
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					PkgID:           "lodash@4.17.0",
					VulnerabilityID: "CVE-2021-1234",
					Fingerprint:     "sha256:f1616ffbc37b9762a217e36f926137a5dd1bcdfa203f5d8f8cd67b787dee969d", // hash(sha256:abc:app1/package.json:lodash@4.17.0:CVE-2021-1234)
				},
			},
		},
		{
			name:       "same vulnerability different artifact produces different fingerprints",
			artifactID: "sha256:xyz",
			target:     "app1/package.json",
			vulns: []types.DetectedVulnerability{
				{
					PkgID:           "lodash@4.17.0",
					VulnerabilityID: "CVE-2021-1234",
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					PkgID:           "lodash@4.17.0",
					VulnerabilityID: "CVE-2021-1234",
					Fingerprint:     "sha256:2ec939f202e5187422d4bdfe2d9f5677d5caefab26713168e238f63d682700dd", // hash(sha256:xyz:app1/package.json:lodash@4.17.0:CVE-2021-1234)
				},
			},
		},
		{
			name:       "same CVE different package version produces different fingerprints",
			artifactID: "sha256:test",
			target:     "app/package.json",
			vulns: []types.DetectedVulnerability{
				{
					PkgID:           "lodash@4.17.0",
					VulnerabilityID: "CVE-2021-1234",
				},
				{
					PkgID:           "lodash@4.17.1",
					VulnerabilityID: "CVE-2021-1234",
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					PkgID:           "lodash@4.17.0",
					VulnerabilityID: "CVE-2021-1234",
					Fingerprint:     "sha256:31a2f37866b537085b9f9bb341e943f079b0c1457a30fc4864d9355e9c84bc72", // hash(sha256:test:app/package.json:lodash@4.17.0:CVE-2021-1234)
				},
				{
					PkgID:           "lodash@4.17.1",
					VulnerabilityID: "CVE-2021-1234",
					Fingerprint:     "sha256:b1efc0cce609f418597be82f5c9840c53ae8ae592ba1672c4f07297d86dbfe7b", // hash(sha256:test:app/package.json:lodash@4.17.1:CVE-2021-1234)
				},
			},
		},
		{
			name:       "empty vulnerabilities",
			artifactID: "sha256:empty",
			target:     "target",
			vulns:      []types.DetectedVulnerability{},
			wantVulns:  []types.DetectedVulnerability{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fillVulnerabilities(tt.artifactID, tt.target, tt.vulns)

			require.Len(t, tt.vulns, len(tt.wantVulns))
			for i, vuln := range tt.vulns {
				// Verify the entire vulnerability object matches expected
				assert.Equal(t, tt.wantVulns[i], vuln, "vulnerability %d mismatch", i)
			}
		})
	}
}
