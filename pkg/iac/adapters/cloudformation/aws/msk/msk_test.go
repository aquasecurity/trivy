package msk

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/msk"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected msk.MSK
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  cluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo: 
        EncryptionInTransit:
          ClientBroker: 'PLAINTEXT'
        EncryptionAtRest:
          DataVolumeKMSKeyId: key
      LoggingInfo: 
        BrokerLogs:
          S3:
            Enabled: true
          CloudWatchLogs:
            Enabled: true
          Firehose:
            Enabled: true
`,
			expected: msk.MSK{
				Clusters: []msk.Cluster{
					{
						EncryptionInTransit: msk.EncryptionInTransit{
							ClientBroker: types.StringTest("PLAINTEXT"),
						},
						EncryptionAtRest: msk.EncryptionAtRest{
							KMSKeyARN: types.StringTest("key"),
							Enabled:   types.BoolTest(true),
						},
						Logging: msk.Logging{
							Broker: msk.BrokerLogging{
								S3: msk.S3Logging{
									Enabled: types.BoolTest(true),
								},
								Firehose: msk.FirehoseLogging{
									Enabled: types.BoolTest(true),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Enabled: types.BoolTest(true),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  cluster:
    Type: AWS::MSK::Cluster
  `,
			expected: msk.MSK{
				Clusters: []msk.Cluster{{
					EncryptionInTransit: msk.EncryptionInTransit{
						ClientBroker: types.StringTest("TLS"),
					},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
