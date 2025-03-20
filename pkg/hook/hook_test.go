package hook_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/hook"
	"github.com/aquasecurity/trivy/pkg/types"
)

type testPostScanner struct{}

func (testPostScanner) Name() string {
	return "test"
}

func (testPostScanner) Version() int {
	return 1
}

func (testPostScanner) PreScan(ctx context.Context, target *types.ScanTarget, options types.ScanOptions) error {
	return nil
}

func (testPostScanner) PostScan(ctx context.Context, results types.Results) (types.Results, error) {
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

func TestScan(t *testing.T) {
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
			s := testPostScanner{}
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
