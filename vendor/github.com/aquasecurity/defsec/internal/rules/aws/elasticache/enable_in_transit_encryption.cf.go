package elasticache

var cloudFormationEnableInTransitEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: 'AWS::ElastiCache::ReplicationGroup'
    Properties:
      AutomaticFailoverEnabled: true    
      CacheNodeType: cache.r3.large
      CacheSubnetGroupName: !Ref CacheSubnetGroup
      Engine: redis
      EngineVersion: '3.2'
      NumNodeGroups: '2'
      ReplicasPerNodeGroup: '3'
      Port: 6379
      PreferredMaintenanceWindow: 'sun:05:00-sun:09:00'
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
      - !Ref ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: '10:00-12:00'   
      TransitEncryptionEnabled: true
`,
}

var cloudFormationEnableInTransitEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: 'AWS::ElastiCache::ReplicationGroup'
    Properties:
      AutomaticFailoverEnabled: true    
      CacheNodeType: cache.r3.large
      CacheSubnetGroupName: !Ref CacheSubnetGroup
      Engine: redis
      EngineVersion: '3.2'
      NumNodeGroups: '2'
      ReplicasPerNodeGroup: '3'
      Port: 6379
      PreferredMaintenanceWindow: 'sun:05:00-sun:09:00'
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
      - !Ref ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: '10:00-12:00'
`,
}

var cloudFormationEnableInTransitEncryptionLinks = []string{}

var cloudFormationEnableInTransitEncryptionRemediationMarkdown = ``
