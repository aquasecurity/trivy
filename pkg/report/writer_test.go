package report_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestResults_Failed(t *testing.T) {
	tests := []struct {
		name    string
		results report.Results
		want    bool
	}{
		{
			name: "no vulnerabilities and misconfigurations",
			results: report.Results{
				{
					Target: "test",
					Type:   "test",
				},
			},
			want: false,
		},
		{
			name: "vulnerabilities found",
			results: report.Results{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.results.Failed()
			assert.Equal(t, tt.want, got)
		})
	}
}
