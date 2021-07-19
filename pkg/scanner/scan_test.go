package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/artifact"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_ScanArtifact(t *testing.T) {
	type args struct {
		options types.ScanOptions
	}
	tests := []struct {
		name               string
		args               args
		inspectExpectation artifact.ArtifactInspectExpectation
		scanExpectation    DriverScanExpectation
		want               report.Report
		wantErr            string
	}{
		{
			name: "happy path",
			args: args{
				options: types.ScanOptions{VulnType: []string{"os"}},
			},
			inspectExpectation: artifact.ArtifactInspectExpectation{
				Args: artifact.ArtifactInspectArgs{
					CtxAnything: true,
				},
				Returns: artifact.ArtifactInspectReturns{
					Reference: ftypes.ArtifactReference{
						Name:        "alpine:3.11",
						ID:          "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
						BlobIDs:     []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
						RepoTags:    []string{"alpine:3.11"},
						RepoDigests: []string{"alpine@sha256:0bd0e9e03a022c3b0226667621da84fc9bf562a9056130424b5bfbd8bcb0397f"},
					},
				},
			},
			scanExpectation: DriverScanExpectation{
				Args: DriverScanArgs{
					Target:   "alpine:3.11",
					ImageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					Options:  types.ScanOptions{VulnType: []string{"os"}},
				},
				Returns: DriverScanReturns{
					Results: report.Results{
						{
							Target: "alpine:3.11",
							Vulnerabilities: []types.DetectedVulnerability{
								{
									VulnerabilityID:  "CVE-2019-9999",
									PkgName:          "vim",
									InstalledVersion: "1.2.3",
									FixedVersion:     "1.2.4",
									Layer: ftypes.Layer{
										Digest: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
										DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
									},
								},
							},
						},
						{
							Target: "node-app/package-lock.json",
							Vulnerabilities: []types.DetectedVulnerability{
								{
									VulnerabilityID:  "CVE-2019-11358",
									PkgName:          "jquery",
									InstalledVersion: "3.3.9",
									FixedVersion:     ">=3.4.0",
								},
							},
							Type: "npm",
						},
					},
					OsFound: &ftypes.OS{
						Family: "alpine",
						Name:   "3.10",
					},
					Eols: true,
				},
			},
			want: report.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.11",
				Metadata: report.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.10",
					},
					RepoTags:    []string{"alpine:3.11"},
					RepoDigests: []string{"alpine@sha256:0bd0e9e03a022c3b0226667621da84fc9bf562a9056130424b5bfbd8bcb0397f"},
				},
				Results: report.Results{
					{
						Target: "alpine:3.11",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2019-9999",
								PkgName:          "vim",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
								Layer: ftypes.Layer{
									Digest: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
									DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
								},
							},
						},
					},
					{
						Target: "node-app/package-lock.json",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2019-11358",
								PkgName:          "jquery",
								InstalledVersion: "3.3.9",
								FixedVersion:     ">=3.4.0",
							},
						},
						Type: "npm",
					},
				},
			},
		},
		{
			name: "sad path: AnalyzerAnalyze returns an error",
			args: args{
				options: types.ScanOptions{VulnType: []string{"os"}},
			},
			inspectExpectation: artifact.ArtifactInspectExpectation{
				Args: artifact.ArtifactInspectArgs{
					CtxAnything: true,
				},
				Returns: artifact.ArtifactInspectReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed analysis",
		},
		{
			name: "sad path: Scan returns an error",
			args: args{
				options: types.ScanOptions{VulnType: []string{"os"}},
			},
			inspectExpectation: artifact.ArtifactInspectExpectation{
				Args: artifact.ArtifactInspectArgs{
					CtxAnything: true,
				},
				Returns: artifact.ArtifactInspectReturns{
					Reference: ftypes.ArtifactReference{
						Name:    "alpine:3.11",
						ID:      "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
						BlobIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					},
				},
			},
			scanExpectation: DriverScanExpectation{
				Args: DriverScanArgs{
					Target:   "alpine:3.11",
					ImageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					Options:  types.ScanOptions{VulnType: []string{"os"}},
				},
				Returns: DriverScanReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "scan failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := new(MockDriver)
			d.ApplyScanExpectation(tt.scanExpectation)

			mockArtifact := new(artifact.MockArtifact)
			mockArtifact.ApplyInspectExpectation(tt.inspectExpectation)

			s := NewScanner(d, mockArtifact)
			got, err := s.ScanArtifact(context.Background(), tt.args.options)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
