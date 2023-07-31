package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/flag"
)

func Test_ARNReport(t *testing.T) {
	tests := []struct {
		name      string
		options   flag.Options
		fromCache bool
		expected  string
	}{
		{
			name: "simple output",
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
					ARN:      "arn:aws:s3:us-east-1:1234567890:bucket1",
					Account:  "1234567890",
				},
			},
			fromCache: false,
			expected: `
Results for 'arn:aws:s3:us-east-1:1234567890:bucket1' (AWS Account 1234567890)


arn:aws:s3:us-east-1:1234567890:bucket1 (cloud)

Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: something failed
════════════════════════════════════════
Bad stuff is... bad

See https://avd.aquasec.com/misconfig/avd-aws-9999
────────────────────────────────────────


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

			output := filepath.Join(t.TempDir(), "output")
			tt.options.Output = output
			require.NoError(t, Write(report, tt.options, tt.fromCache))

			b, err := os.ReadFile(output)
			require.NoError(t, err)

			assert.Equal(t, "AWS", report.Provider)
			assert.Equal(t, tt.options.AWSOptions.Account, report.AccountID)
			assert.Equal(t, tt.options.AWSOptions.Region, report.Region)
			assert.ElementsMatch(t, tt.options.AWSOptions.Services, report.ServicesInScope)
			assert.Equal(t, tt.expected, strings.ReplaceAll(string(b), "\r\n", "\n"))
		})
	}
}
