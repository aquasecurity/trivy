package report

import (
	"sort"
	"testing"

	fanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/defsec/pkg/scan"
)

func Test_ResultConversion(t *testing.T) {

	tests := []struct {
		name     string
		results  scan.Results
		provider string
		scoped   []string
		expected map[string]ResultsAtTime
	}{
		{
			name:     "no results",
			results:  scan.Results{},
			provider: "AWS",
			expected: make(map[string]ResultsAtTime),
		},
		{
			name:     "no results, multiple scoped services",
			results:  scan.Results{},
			provider: "AWS",
			scoped:   []string{"s3", "ec2"},
			expected: map[string]ResultsAtTime{
				"s3":  {},
				"ec2": {},
			},
		},
		{
			name: "multiple results",
			results: func() scan.Results {

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
			}(),
			provider: "AWS",
			expected: map[string]ResultsAtTime{
				"s3": {
					Results: types.Results{
						{
							Target: "arn:aws:s3:us-east-1:1234567890:bucket1",
							Class:  "config",
							Type:   "cloud",
							Misconfigurations: []types.DetectedMisconfiguration{
								{
									Type:        "AWS",
									ID:          "AVD-AWS-9999",
									AVDID:       "AVD-AWS-9999",
									Title:       "Do not use bad stuff",
									Description: "Bad stuff is... bad",
									Message:     "something failed",
									Resolution:  "Remove bad stuff",
									Severity:    "HIGH",
									PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-aws-9999",
									References: []string{
										"https://avd.aquasec.com/misconfig/avd-aws-9999",
									},
									Status: "FAIL",
									CauseMetadata: fanaltypes.CauseMetadata{
										Resource:  "arn:aws:s3:us-east-1:1234567890:bucket1",
										Provider:  "AWS",
										Service:   "s3",
										StartLine: 0,
										EndLine:   0,
										Code:      fanaltypes.Code{},
									},
								},
							},
						},
						{
							Target: "arn:aws:s3:us-east-1:1234567890:bucket2",
							Class:  "config",
							Type:   "cloud",
							Misconfigurations: []types.DetectedMisconfiguration{
								{
									Type:        "AWS",
									ID:          "AVD-AWS-9999",
									AVDID:       "AVD-AWS-9999",
									Title:       "Do not use bad stuff",
									Description: "Bad stuff is... bad",
									Message:     "something else failed",
									Resolution:  "Remove bad stuff",
									Severity:    "HIGH",
									PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-aws-9999",
									References: []string{
										"https://avd.aquasec.com/misconfig/avd-aws-9999",
									},
									Status: "FAIL",
									CauseMetadata: fanaltypes.CauseMetadata{
										Resource: "arn:aws:s3:us-east-1:1234567890:bucket2",
										Provider: "AWS",
										Service:  "s3",
									},
								},
								{
									Type:        "AWS",
									ID:          "AVD-AWS-9999",
									AVDID:       "AVD-AWS-9999",
									Title:       "Do not use bad stuff",
									Description: "Bad stuff is... bad",
									Message:     "something else failed again",
									Resolution:  "Remove bad stuff",
									Severity:    "HIGH",
									PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-aws-9999",
									References: []string{
										"https://avd.aquasec.com/misconfig/avd-aws-9999",
									},
									Status: "FAIL",
									CauseMetadata: fanaltypes.CauseMetadata{
										Resource: "arn:aws:s3:us-east-1:1234567890:bucket2",
										Provider: "AWS",
										Service:  "s3",
									},
								},
							},
						},
					},
				},
				"ec2": {
					Results: types.Results{
						{
							Target: "arn:aws:ec2:us-east-1:1234567890:instance1",
							Class:  "config",
							Type:   "cloud",
							Misconfigurations: []types.DetectedMisconfiguration{
								{
									Type:        "AWS",
									ID:          "AVD-AWS-9999",
									AVDID:       "AVD-AWS-9999",
									Title:       "Do not use bad stuff",
									Description: "Bad stuff is... bad",
									Message:     "instance is bad",
									Resolution:  "Remove bad stuff",
									Severity:    "HIGH",
									PrimaryURL:  "https://avd.aquasec.com/misconfig/avd-aws-9999",
									References: []string{
										"https://avd.aquasec.com/misconfig/avd-aws-9999",
									},
									Status: "FAIL",
									CauseMetadata: fanaltypes.CauseMetadata{
										Resource: "arn:aws:ec2:us-east-1:1234567890:instance1",
										Provider: "AWS",
										Service:  "ec2",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			converted := ConvertResults(test.results, test.provider, test.scoped)
			assertConvertedResultsMatch(t, test.expected, converted)
		})
	}

}

func assertConvertedResultsMatch(t *testing.T, expected, actual map[string]ResultsAtTime) {
	assert.Equal(t, len(expected), len(actual))
	for service, resultsAtTime := range expected {
		_, ok := actual[service]
		assert.True(t, ok)
		sort.Slice(actual[service].Results, func(i, j int) bool {
			return actual[service].Results[i].Target < actual[service].Results[j].Target
		})
		assert.ElementsMatch(t, resultsAtTime.Results, actual[service].Results)
	}
}
