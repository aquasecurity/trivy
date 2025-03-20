package hook_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/hook"
	"github.com/aquasecurity/trivy/pkg/types"
)

type testHook struct{}

func (testHook) Name() string {
	return "test"
}

func (testHook) Version() int {
	return 1
}

// ScanHook implementation
func (testHook) PreScan(ctx context.Context, target *types.ScanTarget, options types.ScanOptions) error {
	if target.Name == "bad-pre" {
		return errors.New("bad pre-scan")
	}
	return nil
}

func (testHook) PostScan(ctx context.Context, results types.Results) (types.Results, error) {
	for i, r := range results {
		if r.Target == "bad" {
			return nil, errors.New("bad")
		}
		for j := range r.Vulnerabilities {
			results[i].Vulnerabilities[j].Severity = "LOW"
		}
	}
	return results, nil
}

// RunHook implementation
func (testHook) PreRun(ctx context.Context, opts flag.Options) error {
	if opts.GlobalOptions.ConfigFile == "bad-config" {
		return errors.New("bad pre-run")
	}
	return nil
}

func (testHook) PostRun(ctx context.Context, opts flag.Options) error {
	if opts.GlobalOptions.ConfigFile == "bad-config" {
		return errors.New("bad post-run")
	}
	return nil
}

// ReportHook implementation
func (testHook) PreReport(ctx context.Context, report *types.Report, opts flag.Options) error {
	if report.ArtifactName == "bad-report" {
		return errors.New("bad pre-report")
	}

	// Modify the report
	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			report.Results[i].Vulnerabilities[j].Title = "Modified by pre-report hook"
		}
	}
	return nil
}

func (testHook) PostReport(ctx context.Context, report *types.Report, opts flag.Options) error {
	if report.ArtifactName == "bad-report" {
		return errors.New("bad post-report")
	}

	// Modify the report
	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			report.Results[i].Vulnerabilities[j].Description = "Modified by post-report hook"
		}
	}
	return nil
}

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
								Severity: "LOW",
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
			s := testHook{}
			hook.RegisterHook(s)
			defer func() {
				hook.DeregisterHook(s.Name())
			}()

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
			s := testHook{}
			hook.RegisterHook(s)
			defer func() {
				hook.DeregisterHook(s.Name())
			}()

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
			s := testHook{}
			hook.RegisterHook(s)
			defer func() {
				hook.DeregisterHook(s.Name())
			}()

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
			s := testHook{}
			hook.RegisterHook(s)
			defer func() {
				hook.DeregisterHook(s.Name())
			}()

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
			s := testHook{}
			hook.RegisterHook(s)
			defer func() {
				hook.DeregisterHook(s.Name())
			}()

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
			s := testHook{}
			hook.RegisterHook(s)
			defer func() {
				hook.DeregisterHook(s.Name())
			}()

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
