package report

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/flag"
)

func Test_ResourceReport(t *testing.T) {
	tests := []struct {
		name      string
		options   flag.Options
		fromCache bool
		expected  string
	}{
		{
			name: "simple table output",
			options: flag.Options{
				ReportOptions: flag.ReportOptions{
					Format: tableFormat,
					Severities: []types.Severity{
						types.SeverityLow,
						types.SeverityMedium,
						types.SeverityHigh,
						types.SeverityCritical,
					},
				},
				AWSOptions: flag.AWSOptions{
					Services: []string{"s3"},
				},
			},
			fromCache: false,
			expected: `
Resource Summary for Service 's3' (AWS Account )
┌─────────────────────────────────────────┬──────────────────────────────────────────┐
│                                         │            Misconfigurations             │
│                                         ├──────────┬──────┬────────┬─────┬─────────┤
│ Resource                                │ Critical │ High │ Medium │ Low │ Unknown │
├─────────────────────────────────────────┼──────────┼──────┼────────┼─────┼─────────┤
│ arn:aws:s3:us-east-1:1234567890:bucket1 │        0 │    1 │      0 │   0 │       0 │
│ arn:aws:s3:us-east-1:1234567890:bucket2 │        0 │    2 │      0 │   0 │       0 │
└─────────────────────────────────────────┴──────────┴──────┴────────┴─────┴─────────┘
`,
		},
		{
			name: "results from cache",
			options: flag.Options{
				ReportOptions: flag.ReportOptions{
					Format: tableFormat,
					Severities: []types.Severity{
						types.SeverityLow,
						types.SeverityMedium,
						types.SeverityHigh,
						types.SeverityCritical,
					},
				},
				AWSOptions: flag.AWSOptions{
					Services: []string{"s3"},
				},
			},
			fromCache: true,
			expected: `
Resource Summary for Service 's3' (AWS Account )
┌─────────────────────────────────────────┬──────────────────────────────────────────┐
│                                         │            Misconfigurations             │
│                                         ├──────────┬──────┬────────┬─────┬─────────┤
│ Resource                                │ Critical │ High │ Medium │ Low │ Unknown │
├─────────────────────────────────────────┼──────────┼──────┼────────┼─────┼─────────┤
│ arn:aws:s3:us-east-1:1234567890:bucket1 │        0 │    1 │      0 │   0 │       0 │
│ arn:aws:s3:us-east-1:1234567890:bucket2 │        0 │    2 │      0 │   0 │       0 │
└─────────────────────────────────────────┴──────────┴──────┴────────┴─────┴─────────┘

This scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.
`,
		},
		{
			name: "no problems",
			options: flag.Options{
				ReportOptions: flag.ReportOptions{
					Format: tableFormat,
					Severities: []types.Severity{
						types.SeverityLow,
					},
				},
				AWSOptions: flag.AWSOptions{
					Services: []string{"s3"},
				},
			},
			fromCache: false,
			expected: `
Resource Summary for Service 's3' (AWS Account )

No problems detected.
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := New(
				"AWS",
				tt.options.AWSOptions.Account,
				tt.options.AWSOptions.Region,
				createTestResults(),
				tt.options.AWSOptions.Services,
			)

			buffer := bytes.NewBuffer([]byte{})
			tt.options.Output = buffer
			require.NoError(t, Write(report, tt.options, tt.fromCache))

			assert.Equal(t, "AWS", report.Provider)
			assert.Equal(t, tt.options.AWSOptions.Account, report.AccountID)
			assert.Equal(t, tt.options.AWSOptions.Region, report.Region)
			assert.ElementsMatch(t, tt.options.AWSOptions.Services, report.ServicesInScope)
			assert.Equal(t, tt.expected, buffer.String())
		})
	}
}
