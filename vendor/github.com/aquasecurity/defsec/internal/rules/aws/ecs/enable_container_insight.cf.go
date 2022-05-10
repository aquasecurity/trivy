package ecs

var cloudFormationEnableContainerInsightGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
`,
}

var cloudFormationEnableContainerInsightBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
`,
}

var cloudFormationEnableContainerInsightLinks = []string{}

var cloudFormationEnableContainerInsightRemediationMarkdown = ``
