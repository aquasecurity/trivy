package elasticsearch

var cloudFormationEnableDomainEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: 'test'
      ElasticsearchVersion: '7.10'
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

var cloudFormationEnableDomainEncryptionBadExamples = []string{
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

var cloudFormationEnableDomainEncryptionLinks = []string{}

var cloudFormationEnableDomainEncryptionRemediationMarkdown = ``
