package hook_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/hooktest"
	"github.com/aquasecurity/trivy/pkg/extension/hook"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestPostScan(t *testing.T) {
	tests := []struct {
		name    string
		results types.Results
		want    types.Results
		wantErr bool
	}{
		{
			name: "happy path",
			results: types.Results{
				{
					Target: "test",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2022-0001",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "CRITICAL",
							},
						},
					},
				},
			},
			want: types.Results{
				{
					Target: "test",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2022-0001",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "CRITICAL",
								References: []string{
									"https://example.com/post-scan",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "sad path",
			results: types.Results{
				{
					Target: "bad",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the test hook
			hooktest.Init(t)

			results, err := hook.PostScan(t.Context(), tt.results)
			require.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, tt.want, results)
		})
	}
}

func TestPreScan(t *testing.T) {
	tests := []struct {
		name    string
		target  *types.ScanTarget
		options types.ScanOptions
		wantErr bool
	}{
		{
			name: "happy path",
			target: &types.ScanTarget{
				Name: "test",
			},
			wantErr: false,
		},
		{
			name: "sad path",
			target: &types.ScanTarget{
				Name: "bad-pre",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the test hook
			hooktest.Init(t)

			err := hook.PreScan(t.Context(), tt.target, tt.options)
			require.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestPreRun(t *testing.T) {
	tests := []struct {
		name    string
		opts    flag.Options
		wantErr bool
	}{
		{
			name:    "happy path",
			opts:    flag.Options{},
			wantErr: false,
		},
		{
			name: "sad path",
			opts: flag.Options{
				GlobalOptions: flag.GlobalOptions{
					ConfigFile: "bad-config",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the test hook
			hooktest.Init(t)

			err := hook.PreRun(t.Context(), tt.opts)
			require.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestPostRun(t *testing.T) {
	tests := []struct {
		name    string
		opts    flag.Options
		wantErr bool
	}{
		{
			name:    "happy path",
			opts:    flag.Options{},
			wantErr: false,
		},
		{
			name: "sad path",
			opts: flag.Options{
				GlobalOptions: flag.GlobalOptions{
					ConfigFile: "bad-config",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the test extension
			hooktest.Init(t)

			err := hook.PostRun(t.Context(), tt.opts)
			require.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestPreReport(t *testing.T) {
	tests := []struct {
		name      string
		report    *types.Report
		opts      flag.Options
		wantTitle string
		wantErr   bool
	}{
		{
			name: "happy path",
			report: &types.Report{
				Results: types.Results{
					{
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID: "CVE-2022-0001",
							},
						},
					},
				},
			},
			wantTitle: "Modified by pre-report hook",
			wantErr:   false,
		},
		{
			name: "sad path",
			report: &types.Report{
				ArtifactName: "bad-report",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the test hook
			hooktest.Init(t)

			err := hook.PreReport(t.Context(), tt.report, tt.opts)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.Len(t, tt.report.Results, 1)
			require.Len(t, tt.report.Results[0].Vulnerabilities, 1)
			assert.Equal(t, tt.wantTitle, tt.report.Results[0].Vulnerabilities[0].Title)
		})
	}
}

func TestPostReport(t *testing.T) {
	tests := []struct {
		name            string
		report          *types.Report
		opts            flag.Options
		wantDescription string
		wantErr         bool
	}{
		{
			name: "happy path",
			report: &types.Report{
				Results: types.Results{
					{
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID: "CVE-2022-0001",
							},
						},
					},
				},
			},
			wantDescription: "Modified by post-report hook",
			wantErr:         false,
		},
		{
			name: "sad path",
			report: &types.Report{
				ArtifactName: "bad-report",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the test hook
			hooktest.Init(t)

			err := hook.PostReport(t.Context(), tt.report, tt.opts)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.Len(t, tt.report.Results, 1)
			require.Len(t, tt.report.Results[0].Vulnerabilities, 1)
			assert.Equal(t, tt.wantDescription, tt.report.Results[0].Vulnerabilities[0].Description)
		})
	}
}
