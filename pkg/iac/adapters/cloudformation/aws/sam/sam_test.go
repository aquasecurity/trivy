package sam

import (
	"testing"

	"github.com/liamg/iamgo"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected sam.SAM
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      Name: test
      TracingEnabled: true
      Domain:
        DomainName: domain
        SecurityPolicy: "TLS_1_2"
      MethodSettings:
        - DataTraceEnabled: true
          CacheDataEncrypted: true
          MetricsEnabled: true
          LoggingLevel: INFO
      AccessLogSetting:
        DestinationArn: 'arn:aws:logs:us-east-1:123456789:log-group:my-log-group'
  HttpApi:
    Type: AWS::Serverless::HttpApi
    Properties:
      Name: test
      Domain:
        DomainName: test
        SecurityPolicy: "TLS_1_2"
      AccessLogSettings:
        DestinationArn: 'arn:aws:logs:us-east-1:123456789:log-group:my-log-group'
      DefaultRouteSettings:
        LoggingLevel: INFO
        DataTraceEnabled: true
        DetailedMetricsEnabled: true
  myFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: test
      Tracing: Active
      Policies:
        - AWSLambdaExecute
        - Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action:
                - s3:GetObject
              Resource: 'arn:aws:s3:::my-bucket/*'
  MySampleStateMachine:
    Type: AWS::Serverless::StateMachine
    Properties:
      Logging:
        Level: ALL
      Tracing:
        Enabled: true
      Policies:
        -  Version: "2012-10-17"
           Statement:
             - Effect: Allow
               Action:
                 - "cloudwatch:*"
               Resource: "*"
  myTable:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: my-table
      SSESpecification:
        SSEEnabled: "true"
        KMSMasterKeyId: "kmskey"
`,
			expected: sam.SAM{
				APIs: []sam.API{
					{
						Name:           types.StringTest("test"),
						TracingEnabled: types.BoolTest(true),
						DomainConfiguration: sam.DomainConfiguration{
							Name:           types.StringTest("domain"),
							SecurityPolicy: types.StringTest("TLS_1_2"),
						},
						AccessLogging: sam.AccessLogging{
							CloudwatchLogGroupARN: types.StringTest("arn:aws:logs:us-east-1:123456789:log-group:my-log-group"),
						},
					},
				},
				HttpAPIs: []sam.HttpAPI{
					{
						Name: types.StringTest("test"),
						DomainConfiguration: sam.DomainConfiguration{
							Name:           types.StringTest("test"),
							SecurityPolicy: types.StringTest("TLS_1_2"),
						},
						AccessLogging: sam.AccessLogging{
							CloudwatchLogGroupARN: types.StringTest("arn:aws:logs:us-east-1:123456789:log-group:my-log-group"),
						},
						DefaultRouteSettings: sam.RouteSettings{
							DataTraceEnabled:       types.BoolTest(true),
							DetailedMetricsEnabled: types.BoolTest(true),
						},
					},
				},
				Functions: []sam.Function{
					{
						FunctionName: types.StringTest("test"),
						Tracing:      types.StringTest("Active"),
						Policies: []iam.Policy{
							{
								Document: func() iam.Document {
									return iam.Document{
										Parsed: iamgo.NewPolicyBuilder().
											WithVersion("2012-10-17").
											WithStatement(
												iamgo.NewStatementBuilder().
													WithEffect("Allow").
													WithActions([]string{"s3:GetObject"}).
													WithResources([]string{"arn:aws:s3:::my-bucket/*"}).
													Build(),
											).
											Build(),
									}
								}(),
							},
						},
						ManagedPolicies: []types.StringValue{
							types.StringTest("AWSLambdaExecute"),
						},
					},
				},
				StateMachines: []sam.StateMachine{
					{
						LoggingConfiguration: sam.LoggingConfiguration{
							LoggingEnabled: types.BoolTest(true),
						},
						Tracing: sam.TracingConfiguration{
							Enabled: types.BoolTest(true),
						},
						Policies: []iam.Policy{
							{
								Document: func() iam.Document {
									return iam.Document{
										Parsed: iamgo.NewPolicyBuilder().
											WithVersion("2012-10-17").
											WithStatement(
												iamgo.NewStatementBuilder().
													WithEffect("Allow").
													WithActions([]string{"cloudwatch:*"}).
													WithResources([]string{"*"}).
													Build(),
											).
											Build(),
									}
								}(),
							},
						},
					},
				},
				SimpleTables: []sam.SimpleTable{
					{
						TableName: types.StringTest("my-table"),
						SSESpecification: sam.SSESpecification{
							Enabled:        types.BoolTest(true),
							KMSMasterKeyID: types.StringTest("kmskey"),
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::Api
  HttpApi:
    Type: AWS::Serverless::HttpApi
  myFunction:
    Type: AWS::Serverless::Function
  MySampleStateMachine:
    Type: AWS::Serverless::StateMachine
  myTable:
    Type: AWS::Serverless::SimpleTable
`,
			expected: sam.SAM{
				APIs:          []sam.API{{}},
				HttpAPIs:      []sam.HttpAPI{{}},
				Functions:     []sam.Function{{}},
				StateMachines: []sam.StateMachine{{}},
				SimpleTables:  []sam.SimpleTable{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
