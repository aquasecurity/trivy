package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"

	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"github.com/aquasecurity/defsec/pkg/scan"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Test_ServiceReport(t *testing.T) {
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
			},
			fromCache: false,
			expected: `
Scan Overview for AWS Account 
┌─────────┬──────────────────────────────────────────────────┬──────────────┐
│         │                Misconfigurations                 │              │
│         ├──────────┬──────────────┬────────┬─────┬─────────┤              │
│ Service │ Critical │     High     │ Medium │ Low │ Unknown │ Last Scanned │
├─────────┼──────────┼──────────────┼────────┼─────┼─────────┼──────────────┤
│ ec2     │        0 │            1 │      0 │   0 │       0 │ just now     │
│ s3      │        0 │            3 │      0 │   0 │       0 │ just now     │
└─────────┴──────────┴──────────────┴────────┴─────┴─────────┴──────────────┘
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
			},
			fromCache: true,
			expected: `
Scan Overview for AWS Account 
┌─────────┬──────────────────────────────────────────────────┬──────────────┐
│         │                Misconfigurations                 │              │
│         ├──────────┬──────────────┬────────┬─────┬─────────┤              │
│ Service │ Critical │     High     │ Medium │ Low │ Unknown │ Last Scanned │
├─────────┼──────────┼──────────────┼────────┼─────┼─────────┼──────────────┤
│ ec2     │        0 │            1 │      0 │   0 │       0 │ just now     │
│ s3      │        0 │            3 │      0 │   0 │       0 │ just now     │
└─────────┴──────────┴──────────────┴────────┴─────┴─────────┴──────────────┘

This scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.
`,
		},
		{
			name: "filter severities",
			options: flag.Options{
				ReportOptions: flag.ReportOptions{
					Format: tableFormat,
					Severities: []types.Severity{
						types.SeverityMedium,
					},
				},
				AWSOptions: flag.AWSOptions{
					Services: []string{"s3", "ec2"},
				},
			},
			fromCache: false,
			expected: `
Scan Overview for AWS Account 
┌─────────┬──────────────────────────────────────────────────┬──────────────┐
│         │                Misconfigurations                 │              │
│         ├──────────┬──────────────┬────────┬─────┬─────────┤              │
│ Service │ Critical │     High     │ Medium │ Low │ Unknown │ Last Scanned │
├─────────┼──────────┼──────────────┼────────┼─────┼─────────┼──────────────┤
│ ec2     │        0 │            0 │      0 │   0 │       0 │ just now     │
│ s3      │        0 │            0 │      0 │   0 │       0 │ just now     │
└─────────┴──────────┴──────────────┴────────┴─────┴─────────┴──────────────┘
`,
		},
		{
			name: "scoped services without results",
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
					Services: []string{"ec2", "s3", "iam"},
				},
			},
			fromCache: false,
			expected: `
Scan Overview for AWS Account 
┌─────────┬──────────────────────────────────────────────────┬──────────────┐
│         │                Misconfigurations                 │              │
│         ├──────────┬──────────────┬────────┬─────┬─────────┤              │
│ Service │ Critical │     High     │ Medium │ Low │ Unknown │ Last Scanned │
├─────────┼──────────┼──────────────┼────────┼─────┼─────────┼──────────────┤
│ ec2     │        0 │            1 │      0 │   0 │       0 │ just now     │
│ iam     │        0 │            0 │      0 │   0 │       0 │ just now     │
│ s3      │        0 │            3 │      0 │   0 │       0 │ just now     │
└─────────┴──────────┴──────────────┴────────┴─────┴─────────┴──────────────┘
`,
		},
		{
			name: "json output",
			options: flag.Options{
				ReportOptions: flag.ReportOptions{
					Format: "json",
					Severities: []types.Severity{
						types.SeverityLow,
						types.SeverityMedium,
						types.SeverityHigh,
						types.SeverityCritical,
					},
				},
			},
			fromCache: false,
			expected: `{
  "ArtifactType": "aws_account",
  "Metadata": {
    "ImageConfig": {
      "architecture": "",
      "created": "0001-01-01T00:00:00Z",
      "os": "",
      "rootfs": {
        "type": "",
        "diff_ids": null
      },
      "config": {}
    }
  },
  "Results": [
    {
      "Target": "arn:aws:ec2:us-east-1:1234567890:instance1",
      "Class": "config",
      "Type": "cloud",
      "MisconfSummary": {
        "Successes": 0,
        "Failures": 1,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "AWS",
          "ID": "AVD-AWS-9999",
          "AVDID": "AVD-AWS-9999",
          "Title": "Do not use bad stuff",
          "Description": "Bad stuff is... bad",
          "Message": "instance is bad",
          "Resolution": "Remove bad stuff",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-9999",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-9999"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:ec2:us-east-1:1234567890:instance1",
            "Provider": "AWS",
            "Service": "ec2",
            "Code": {
              "Lines": null
            }
          }
        }
      ]
    },
    {
      "Target": "arn:aws:s3:us-east-1:1234567890:bucket1",
      "Class": "config",
      "Type": "cloud",
      "MisconfSummary": {
        "Successes": 0,
        "Failures": 1,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "AWS",
          "ID": "AVD-AWS-9999",
          "AVDID": "AVD-AWS-9999",
          "Title": "Do not use bad stuff",
          "Description": "Bad stuff is... bad",
          "Message": "something failed",
          "Resolution": "Remove bad stuff",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-9999",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-9999"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:us-east-1:1234567890:bucket1",
            "Provider": "AWS",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        }
      ]
    },
    {
      "Target": "arn:aws:s3:us-east-1:1234567890:bucket2",
      "Class": "config",
      "Type": "cloud",
      "MisconfSummary": {
        "Successes": 0,
        "Failures": 2,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "AWS",
          "ID": "AVD-AWS-9999",
          "AVDID": "AVD-AWS-9999",
          "Title": "Do not use bad stuff",
          "Description": "Bad stuff is... bad",
          "Message": "something else failed",
          "Resolution": "Remove bad stuff",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-9999",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-9999"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:us-east-1:1234567890:bucket2",
            "Provider": "AWS",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-9999",
          "AVDID": "AVD-AWS-9999",
          "Title": "Do not use bad stuff",
          "Description": "Bad stuff is... bad",
          "Message": "something else failed again",
          "Resolution": "Remove bad stuff",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-9999",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-9999"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:us-east-1:1234567890:bucket2",
            "Provider": "AWS",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        }
      ]
    },
    {
      "Target": "arn:aws:s3:us-east-1:1234567890:bucket3",
      "Class": "config",
      "Type": "cloud",
      "MisconfSummary": {
        "Successes": 1,
        "Failures": 0,
        "Exceptions": 0
      }
    }
  ]
}`,
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

			assert.Equal(t, "AWS", report.Provider)
			assert.Equal(t, tt.options.AWSOptions.Account, report.AccountID)
			assert.Equal(t, tt.options.AWSOptions.Region, report.Region)
			assert.ElementsMatch(t, tt.options.AWSOptions.Services, report.ServicesInScope)

			b, err := os.ReadFile(output)
			require.NoError(t, err)
			if tt.options.Format == "json" {
				// json output can be formatted/ordered differently - we just care that the data matches
				assert.JSONEq(t, tt.expected, string(b))
			} else {
				assert.Equal(t, tt.expected, string(b))
			}
		})
	}
}

func createTestResults() scan.Results {

	baseRule := scan.Rule{
		AVDID:       "AVD-AWS-9999",
		Aliases:     []string{"AWS999"},
		ShortCode:   "no-bad-stuff",
		Summary:     "Do not use bad stuff",
		Explanation: "Bad stuff is... bad",
		Impact:      "Bad things",
		Resolution:  "Remove bad stuff",
		Provider:    "AWS",
		Severity:    "HIGH",
	}

	var s3Results scan.Results
	s3Results.Add(
		"something failed",
		defsecTypes.NewRemoteMetadata((arn.ARN{
			Partition: "aws",
			Service:   "s3",
			Region:    "us-east-1",
			AccountID: "1234567890",
			Resource:  "bucket1",
		}).String()),
	)
	s3Results.Add(
		"something else failed",
		defsecTypes.NewRemoteMetadata((arn.ARN{
			Partition: "aws",
			Service:   "s3",
			Region:    "us-east-1",
			AccountID: "1234567890",
			Resource:  "bucket2",
		}).String()),
	)
	s3Results.Add(
		"something else failed again",
		defsecTypes.NewRemoteMetadata((arn.ARN{
			Partition: "aws",
			Service:   "s3",
			Region:    "us-east-1",
			AccountID: "1234567890",
			Resource:  "bucket2",
		}).String()),
	)
	s3Results.AddPassed(
		defsecTypes.NewRemoteMetadata((arn.ARN{
			Partition: "aws",
			Service:   "s3",
			Region:    "us-east-1",
			AccountID: "1234567890",
			Resource:  "bucket3",
		}).String()),
	)
	baseRule.Service = "s3"
	s3Results.SetRule(baseRule)
	var ec2Results scan.Results
	ec2Results.Add(
		"instance is bad",
		defsecTypes.NewRemoteMetadata((arn.ARN{
			Partition: "aws",
			Service:   "ec2",
			Region:    "us-east-1",
			AccountID: "1234567890",
			Resource:  "instance1",
		}).String()),
	)
	baseRule.Service = "ec2"
	ec2Results.SetRule(baseRule)
	return append(s3Results, ec2Results...)
}
