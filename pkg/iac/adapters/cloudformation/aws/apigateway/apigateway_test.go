package apigateway

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway"
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
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
  MyRestApi:
    Type: 'AWS::ApiGateway::RestApi'
    Properties:
      Description: A test API
      Name: MyRestAPI
  ApiResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref MyRestApi
  MethodPOST:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref MyRestApi
      ResourceId: !Ref ApiResource
      HttpMethod: POST
      AuthorizationType: COGNITO_USER_POOLS
      ApiKeyRequired: true
  Stage:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      RestApiId: !Ref MyRestApi
      TracingEnabled: true
      AccessLogSetting:
        DestinationArn: test-arn
      MethodSettings:
        - CacheDataEncrypted: true
          CachingEnabled: true
          HttpMethod: POST
  MyDomainName:
    Type: AWS::ApiGateway::DomainName
    Properties:
      DomainName: mydomainame.us-east-1.com
      SecurityPolicy: "TLS_1_2"

  MyApi2:
    Type: 'AWS::ApiGatewayV2::Api'
    Properties:
      Name: MyApi2
      ProtocolType: WEBSOCKET
  MyStage2:
    Type: 'AWS::ApiGatewayV2::Stage'
    Properties:
      StageName: Prod
      ApiId: !Ref MyApi2
      AccessLogSettings:
        DestinationArn: some-arn
  MyDomainName2:
    Type: 'AWS::ApiGatewayV2::DomainName'
    Properties:
      DomainName: mydomainame.us-east-1.com
      DomainNameConfigurations:
        - SecurityPolicy: "TLS_1_2"
`,
			expected: apigateway.APIGateway{
				V1: v1.APIGateway{
					APIs: []v1.API{
						{
							Name: types.StringTest("MyRestAPI"),
							Stages: []v1.Stage{
								{
									Name:               types.StringTest("Prod"),
									XRayTracingEnabled: types.BoolTest(true),
									AccessLogging: v1.AccessLogging{
										CloudwatchLogGroupARN: types.StringTest("test-arn"),
									},
									RESTMethodSettings: []v1.RESTMethodSettings{
										{
											Method:             types.StringTest("POST"),
											CacheDataEncrypted: types.BoolTest(true),
											CacheEnabled:       types.BoolTest(true),
										},
									},
								},
							},
							Resources: []v1.Resource{
								{
									Methods: []v1.Method{
										{
											HTTPMethod:        types.StringTest("POST"),
											AuthorizationType: types.StringTest("COGNITO_USER_POOLS"),
											APIKeyRequired:    types.BoolTest(true),
										},
									},
								},
							},
						},
					},
					DomainNames: []v1.DomainName{
						{
							Name:           types.StringTest("mydomainame.us-east-1.com"),
							SecurityPolicy: types.StringTest("TLS_1_2"),
						},
					},
				},
				V2: v2.APIGateway{
					APIs: []v2.API{
						{
							Name:         types.StringTest("MyApi2"),
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
					DomainNames: []v2.DomainName{
						{
							Name:           types.StringTest("mydomainame.us-east-1.com"),
							SecurityPolicy: types.StringTest("TLS_1_2"),
						},
					},
				},
			},
		},
		{
			name: "multiple resources and stages",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Api:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: demo
  Items:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref Api
  Users:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref Api
  ItemsGet:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref Api
      ResourceId: !Ref Items
      HttpMethod: GET
      AuthorizationType: NONE
  UsersPost:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref Api
      ResourceId: !Ref Users
      HttpMethod: POST
      AuthorizationType: AWS_IAM
  Dev:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref Api
      StageName: dev
  Prod:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref Api
      StageName: prod
`,
			expected: apigateway.APIGateway{
				V1: v1.APIGateway{
					APIs: []v1.API{
						{
							Name: types.StringTest("demo"),
							Stages: []v1.Stage{
								{Name: types.StringTest("dev")},
								{Name: types.StringTest("prod")},
							},
							Resources: []v1.Resource{
								{
									Methods: []v1.Method{
										{
											HTTPMethod:        types.StringTest("GET"),
											AuthorizationType: types.StringTest("NONE"),
										},
									},
								},
								{
									Methods: []v1.Method{
										{
											HTTPMethod:        types.StringTest("POST"),
											AuthorizationType: types.StringTest("AWS_IAM"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "v2 api with multiple stages",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Api:
    Type: AWS::ApiGatewayV2::Api
    Properties:
      Name: demo
      ProtocolType: HTTP
  Dev:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      ApiId: !Ref Api
      StageName: dev
      AccessLogSettings:
        DestinationArn: dev-arn
  Prod:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      ApiId: !Ref Api
      StageName: prod
  Other:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      ApiId: other-api
      StageName: other
`,
			expected: apigateway.APIGateway{
				V2: v2.APIGateway{
					APIs: []v2.API{
						{
							Name:         types.StringTest("demo"),
							ProtocolType: types.StringTest("HTTP"),
							Stages: []v2.Stage{
								{
									Name: types.StringTest("dev"),
									AccessLogging: v2.AccessLogging{
										CloudwatchLogGroupARN: types.StringTest("dev-arn"),
									},
								},
								{Name: types.StringTest("prod")},
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
