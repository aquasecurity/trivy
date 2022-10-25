package post_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/scanner/post"

	"github.com/aquasecurity/trivy/pkg/types"
)

type testPostScanner struct{}

func (testPostScanner) Name() string {
	return "test"
}

func (testPostScanner) Version() int {
	return 1
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
			post.RegisterPostScanner(s)
			defer func() {
				post.DeregisterPostScanner(s.Name())
			}()

			results, err := post.Scan(context.Background(), tt.results)
			require.Equal(t, err != nil, tt.wantErr)
			assert.Equal(t, results, tt.want)
		})
	}
}
