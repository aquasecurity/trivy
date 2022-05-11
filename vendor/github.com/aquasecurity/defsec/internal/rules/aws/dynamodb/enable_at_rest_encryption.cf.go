package dynamodb

var cloudFormationEnableAtRestEncryptionGoodExamples = []string{
	`---
Resources:
  daxCluster:
    Type: AWS::DAX::Cluster
    Properties:
      ClusterName: "MyDAXCluster"
      NodeType: "dax.r3.large"
      ReplicationFactor: 1
      IAMRoleARN: "arn:aws:iam::111122223333:role/DaxAccess"
      Description: "DAX cluster created with CloudFormation"
      SSESpecification:
        SSEEnabled: true
`,
}

var cloudFormationEnableAtRestEncryptionBadExamples = []string{
	`---
Resources:
  daxCluster:
    Type: AWS::DAX::Cluster
    Properties:
      ClusterName: "MyDAXCluster"
      NodeType: "dax.r3.large"
      ReplicationFactor: 1
      IAMRoleARN: "arn:aws:iam::111122223333:role/DaxAccess"
      Description: "DAX cluster created with CloudFormation"
      SubnetGroupName: !Ref subnetGroupClu
`,
}

var cloudFormationEnableAtRestEncryptionLinks = []string{}

var cloudFormationEnableAtRestEncryptionRemediationMarkdown = ``
