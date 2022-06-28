package report_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestResults_Failed(t *testing.T) {
	tests := []struct {
		name    string
		results types.Results
		want    bool
	}{
		{
			name: "no vulnerabilities and misconfigurations",
			results: types.Results{
				{
					Target: "test",
					Type:   "test",
				},
			},
			want: false,
		},
		{
			name: "vulnerabilities found",
			results: types.Results{
				{
					Target: "test",
					Type:   "test",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID: "CVE-2021-0001",
							PkgName:         "test",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "failed misconfigurations",
			results: types.Results{
				{
					Target: "test",
					Type:   "test",
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:   "Docker Security Check",
							ID:     "ID-001",
							Status: types.StatusFailure,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "passed misconfigurations",
			results: types.Results{
				{
					Target: "test",
					Type:   "test",
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:   "Docker Security Check",
							ID:     "ID-001",
							Status: types.StatusPassed,
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.results.Failed()
			assert.Equal(t, tt.want, got)
		})
	}
}
