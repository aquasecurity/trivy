package sam

var cloudFormationEnableStateMachineTracingGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  GoodStateMachine:
    Type: AWS::Serverless::StateMachine
    Properties:
      Definition:
        StartAt: MyLambdaState
        States:
          MyLambdaState:
            Type: Task
            Resource: arn:aws:lambda:us-east-1:123456123456:function:my-sample-lambda-app
            End: true
      Role: arn:aws:iam::123456123456:role/service-role/my-sample-role
      Tracing:
        Enabled: true
`,
}

var cloudFormationEnableStateMachineTracingBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM API
Resources:
  BadStateMachine:
    Type: AWS::Serverless::StateMachine
    Properties:
      Definition:
        StartAt: MyLambdaState
        States:
          MyLambdaState:
            Type: Task
            Resource: arn:aws:lambda:us-east-1:123456123456:function:my-sample-lambda-app
            End: true
      Role: arn:aws:iam::123456123456:role/service-role/my-sample-role
      Tracing:
        Enabled: false
`, `---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM API
Resources:
  BadStateMachine:
    Type: AWS::Serverless::StateMachine
    Properties:
      Definition:
        StartAt: MyLambdaState
        States:
          MyLambdaState:
            Type: Task
            Resource: arn:aws:lambda:us-east-1:123456123456:function:my-sample-lambda-app
            End: true
      Role: arn:aws:iam::123456123456:role/service-role/my-sample-role
`,
}

var cloudFormationEnableStateMachineTracingLinks = []string{}

var cloudFormationEnableStateMachineTracingRemediationMarkdown = ``
