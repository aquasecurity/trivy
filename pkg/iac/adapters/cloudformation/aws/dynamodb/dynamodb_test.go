package dynamodb

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected dynamodb.DynamoDB
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  daxCluster:
    Type: AWS::DAX::Cluster
    Properties:
      SSESpecification:
        SSEEnabled: true
  DDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      SSESpecification:
        SSEEnabled: true
        KMSMasterKeyId: "test"
      PointInTimeRecoverySpecification:
        PointInTimeRecoveryEnabled: true

`,
			expected: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled: types.BoolTest(true),
						},
					},
				},
				Tables: []dynamodb.Table{
					{
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  types.BoolTest(true),
							KMSKeyID: types.StringTest("test"),
						},
						PointInTimeRecovery: types.BoolTest(true),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  daxCluster:
    Type: AWS::DAX::Cluster
  DDBTable:
    Type: AWS::DynamoDB::Table
  `,
			expected: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{{}},
				Tables: []dynamodb.Table{
					{
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							KMSKeyID: types.StringTest("alias/aws/dynamodb"),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
