package neptune

var cloudFormationEnableLogExportGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - audit


`,
}

var cloudFormationEnableLogExportBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - debug

`,
}

var cloudFormationEnableLogExportLinks = []string{}

var cloudFormationEnableLogExportRemediationMarkdown = ``
