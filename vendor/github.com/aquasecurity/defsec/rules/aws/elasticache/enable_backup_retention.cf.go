package elasticache

var cloudFormationEnableBackupRetentionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      AZMode: cross-az
      CacheNodeType: cache.m3.medium
      Engine: redis
      NumCacheNodes: '3'
      SnapshotRetentionLimit: 7
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b 
`,
}

var cloudFormationEnableBackupRetentionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      AZMode: cross-az
      CacheNodeType: cache.m3.medium
      Engine: redis
      NumCacheNodes: '3'
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b 
`,
}

var cloudFormationEnableBackupRetentionLinks = []string{}

var cloudFormationEnableBackupRetentionRemediationMarkdown = ``
