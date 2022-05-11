package kinesis

var cloudFormationEnableInTransitEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: GoodExample
      RetentionPeriodHours: 168
      ShardCount: 3
      StreamEncryption:
        EncryptionType: KMS
        KeyId: alis/key
      Tags:
        -
          Key: Environment 
          Value: Production
`,
}

var cloudFormationEnableInTransitEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: BadExample
      RetentionPeriodHours: 168
      ShardCount: 3
      Tags:
        -
          Key: Environment 
          Value: Production

`,
}

var cloudFormationEnableInTransitEncryptionLinks = []string{}

var cloudFormationEnableInTransitEncryptionRemediationMarkdown = ``
