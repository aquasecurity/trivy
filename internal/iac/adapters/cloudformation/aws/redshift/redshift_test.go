package redshift

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected redshift.Redshift
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  myCluster:
    Type: "AWS::Redshift::Cluster"
    Properties:
      DBName: "mydb"
      ClusterIdentifier: myexamplecluster
      AllowVersionUpgrade: false
      MasterUsername: "master"
      NodeType: "ds2.xlarge"
      NumberOfNodes: 2
      PubliclyAccessible: true
      AutomatedSnapshotRetentionPeriod: 2
      Encrypted: true
      KmsKeyId: key
      Endpoint:
        Port: 2000
      ClusterSubnetGroupName: test
  myClusterParameterGroup:
    Type: "AWS::Redshift::ClusterParameterGroup"
    Properties:
      Parameters:
        -
          ParameterName: "enable_user_activity_logging"
          ParameterValue: "true"
  mySecGroup:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: test
  `,
			expected: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						ClusterIdentifier:                types.StringTest("myexamplecluster"),
						AllowVersionUpgrade:              types.BoolTest(false),
						MasterUsername:                   types.StringTest("master"),
						NodeType:                         types.StringTest("ds2.xlarge"),
						NumberOfNodes:                    types.IntTest(2),
						PubliclyAccessible:               types.BoolTest(true),
						AutomatedSnapshotRetentionPeriod: types.IntTest(2),
						Encryption: redshift.Encryption{
							Enabled:  types.BoolTest(true),
							KMSKeyID: types.StringTest("key"),
						},
						EndPoint: redshift.EndPoint{
							Port: types.IntTest(2000),
						},
						SubnetGroupName: types.StringTest("test"),
					},
				},
				ClusterParameters: []redshift.ClusterParameter{
					{
						ParameterName:  types.StringTest("enable_user_activity_logging"),
						ParameterValue: types.StringTest("true"),
					},
				},
				SecurityGroups: []redshift.SecurityGroup{
					{
						Description: types.StringTest("test"),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myCluster:
    Type: "AWS::Redshift::Cluster"
  mySecGroup:
    Type: AWS::Redshift::ClusterSecurityGroup
  myClusterParameterGroup:
    Type: "AWS::Redshift::ClusterParameterGroup"
`,
			expected: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						AllowVersionUpgrade:              types.BoolTest(true),
						AutomatedSnapshotRetentionPeriod: types.IntTest(1),
						NumberOfNodes:                    types.IntTest(1),
					},
				},
				SecurityGroups: []redshift.SecurityGroup{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
