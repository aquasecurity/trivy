package apigateway

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway"
	v2 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v2"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected apigateway.APIGateway
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyApi:
    Type: 'AWS::ApiGatewayV2::Api'
    Properties:
      Name: MyApi
      ProtocolType: WEBSOCKET
  MyStage:
    Type: 'AWS::ApiGatewayV2::Stage'
    Properties:
      StageName: Prod
      ApiId: !Ref MyApi
      AccessLogSettings:
        DestinationArn: some-arn
`,
			expected: apigateway.APIGateway{
				V2: v2.APIGateway{
					APIs: []v2.API{
						{
							Name:         types.StringTest("MyApi"),
							ProtocolType: types.StringTest("WEBSOCKET"),
							Stages: []v2.Stage{
								{
									Name: types.StringTest("Prod"),
									AccessLogging: v2.AccessLogging{
										CloudwatchLogGroupARN: types.StringTest("some-arn"),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyApi:
    Type: 'AWS::ApiGatewayV2::Api'
  MyStage:
    Type: 'AWS::ApiGatewayV2::Stage'
  MyStage2:
    Type: 'AWS::ApiGatewayV2::Stage'
    Properties:
      ApiId: !Ref MyApi
`,
			expected: apigateway.APIGateway{
				V2: v2.APIGateway{
					APIs: []v2.API{
						{
							Stages: []v2.Stage{{}},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
