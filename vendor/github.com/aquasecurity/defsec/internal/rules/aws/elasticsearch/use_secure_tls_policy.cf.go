package elasticsearch

var cloudFormationUseSecureTlsPolicyGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: 'test'
      ElasticsearchVersion: '7.10'
      DomainEndpointOptions:
        TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07
      EncryptionAtRestOptions:
        Enabled: true
        KmsKeyId: alias/kmskey
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: true
        InstanceCount: '2'
        ZoneAwarenessEnabled: true
        InstanceType: 'm3.medium.elasticsearch'
        DedicatedMasterType: 'm3.medium.elasticsearch'
        DedicatedMasterCount: '3'
      EBSOptions:
        EBSEnabled: true
        Iops: '0'
        VolumeSize: '20'
        VolumeType: 'gp2'
`,
}

var cloudFormationUseSecureTlsPolicyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: 'test'
      ElasticsearchVersion: '7.10'
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: true
        InstanceCount: '2'
        ZoneAwarenessEnabled: true
        InstanceType: 'm3.medium.elasticsearch'
        DedicatedMasterType: 'm3.medium.elasticsearch'
        DedicatedMasterCount: '3'
      EBSOptions:
        EBSEnabled: true
        Iops: '0'
        VolumeSize: '20'
        VolumeType: 'gp2'
`,
}

var cloudFormationUseSecureTlsPolicyLinks = []string{}

var cloudFormationUseSecureTlsPolicyRemediationMarkdown = ``
