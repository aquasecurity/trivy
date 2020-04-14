package scanner

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	code := m.Run()
	os.Exit(code)
}

func TestScanner_ScanImage(t *testing.T) {
	type args struct {
		options types.ScanOptions
	}
	tests := []struct {
		name               string
		args               args
		analyzeExpectation AnalyzerAnalyzeExpectation
		scanExpectation    ScanExpectation
		want               report.Results
		wantErr            string
	}{
		{
			name: "happy path",
			args: args{
				options: types.ScanOptions{VulnType: []string{"os"}},
			},
			analyzeExpectation: AnalyzerAnalyzeExpectation{
				Args: AnalyzerAnalyzeArgs{
					CtxAnything: true,
				},
				Returns: AnalyzerAnalyzeReturns{
					Info: ftypes.ImageReference{
						Name:     "alpine:3.11",
						ID:       "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
						LayerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					},
				},
			},
			scanExpectation: ScanExpectation{
				Args: ScanArgs{
					Target:   "alpine:3.11",
					ImageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					Options:  types.ScanOptions{VulnType: []string{"os"}},
				},
				Returns: ScanReturns{
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
					},
					OsFound: &ftypes.OS{
						Family: "alpine",
						Name:   "3.10",
					},
					Eols: true,
				},
			},
			want: report.Results{
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
			},
		},
		{
			name: "sad path: AnalyzerAnalyze returns an error",
			args: args{
				options: types.ScanOptions{VulnType: []string{"os"}},
			},
			analyzeExpectation: AnalyzerAnalyzeExpectation{
				Args: AnalyzerAnalyzeArgs{
					CtxAnything: true,
				},
				Returns: AnalyzerAnalyzeReturns{
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
			analyzeExpectation: AnalyzerAnalyzeExpectation{
				Args: AnalyzerAnalyzeArgs{
					CtxAnything: true,
				},
				Returns: AnalyzerAnalyzeReturns{
					Info: ftypes.ImageReference{
						Name:     "alpine:3.11",
						ID:       "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
						LayerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					},
				},
			},
			scanExpectation: ScanExpectation{
				Args: ScanArgs{
					Target:   "alpine:3.11",
					ImageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
					LayerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
					Options:  types.ScanOptions{VulnType: []string{"os"}},
				},
				Returns: ScanReturns{
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

			analyzer := new(MockAnalyzer)
			analyzer.ApplyAnalyzeExpectation(tt.analyzeExpectation)

			s := NewScanner(d, analyzer)
			got, err := s.ScanImage(tt.args.options)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
