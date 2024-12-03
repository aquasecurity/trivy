package apigateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway"
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
	v2 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v2"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  apigateway.APIGateway
	}{
		{
			name: "basic",
			terraform: `
resource "aws_api_gateway_rest_api" "MyDemoAPI" {
  name        = "MyDemoAPI"
  description = "This is my API for demonstration purposes"
}
resource "aws_api_gateway_resource" "example" {
    rest_api_id = aws_api_gateway_rest_api.MyDemoAPI.id
}
resource "aws_api_gateway_method" "example" {
    rest_api_id = aws_api_gateway_rest_api.MyDemoAPI.id
	resource_id = aws_api_gateway_resource.example.id
    http_method      = "GET"
    authorization    = "NONE"
}
resource "aws_apigatewayv2_api" "example" {
    name = "tfsec"
    protocol_type = "HTTP"
}


resource "aws_apigatewayv2_stage" "example" {
    api_id = aws_apigatewayv2_api.example.id
    name = "tfsec" 
    access_log_settings {
        destination_arn = "arn:123"
    }
}

resource "aws_api_gateway_domain_name" "example" {
    domain_name = "v1.com"
    security_policy = "TLS_1_0"
}

resource "aws_apigatewayv2_domain_name" "example" {
    domain_name = "v2.com"
    domain_name_configuration {
        security_policy = "TLS_1_2"
    }
}
`,
			expected: apigateway.APIGateway{
				V1: v1.APIGateway{
					APIs: []v1.API{
						{
							Metadata: iacTypes.Metadata{},
							Name:     String("MyDemoAPI"),
							Resources: []v1.Resource{
								{
									Methods: []v1.Method{
										{
											HTTPMethod:        String(http.MethodGet),
											AuthorizationType: String("NONE"),
											APIKeyRequired:    Bool(false),
										},
									},
								},
							},
						},
					},
					DomainNames: []v1.DomainName{
						{
							Name:           String("v1.com"),
							SecurityPolicy: String("TLS_1_0"),
						},
					},
				},
				V2: v2.APIGateway{
					APIs: []v2.API{
						{
							Name:         String("tfsec"),
							ProtocolType: String("HTTP"),
							Stages: []v2.Stage{
								{
									Name: String("tfsec"),
									AccessLogging: v2.AccessLogging{
										CloudwatchLogGroupARN: String("arn:123"),
									},
								},
							},
						},
					},
					DomainNames: []v2.DomainName{
						{
							Name:           String("v2.com"),
							SecurityPolicy: String("TLS_1_2"),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Int(i int) iacTypes.IntValue {
	return iacTypes.Int(i, iacTypes.NewTestMetadata())
}

func Bool(b bool) iacTypes.BoolValue {
	return iacTypes.Bool(b, iacTypes.NewTestMetadata())
}

func String(s string) iacTypes.StringValue {
	return iacTypes.String(s, iacTypes.NewTestMetadata())
}
func TestLines(t *testing.T) {
	src := `
	resource "aws_api_gateway_rest_api" "MyDemoAPI" {
		name        = "MyDemoAPI"
		description = "This is my API for demonstration purposes"
	  }
	  
	  resource "aws_api_gateway_resource" "example" {
		rest_api_id = aws_api_gateway_rest_api.MyDemoAPI.id
      }

	  resource "aws_api_gateway_method" "example" {
		  rest_api_id = aws_api_gateway_rest_api.MyDemoAPI.id 
          resource_id = aws_api_gateway_resource.example.id
		  http_method      = "GET"
		  authorization    = "NONE"
		  api_key_required = true
	  }

	  resource "aws_apigatewayv2_api" "example" {
		  name = "tfsec"
		  protocol_type = "HTTP"
	  }
	  
	  resource "aws_apigatewayv2_stage" "example" {
		  api_id = aws_apigatewayv2_api.example.id
		  name = "tfsec" 
		  access_log_settings {
			  destination_arn = "arn:123"
		  }
	  }
	  
	  resource "aws_api_gateway_domain_name" "example" {
		  domain_name = "v1.com"
		  security_policy = "TLS_1_0"
	  }

	`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.V1.APIs, 1)
	require.Len(t, adapted.V2.APIs, 1)
	require.Len(t, adapted.V1.DomainNames, 1)

	apiV1 := adapted.V1.APIs[0]
	apiV2 := adapted.V2.APIs[0]
	domainName := adapted.V1.DomainNames[0]

	assert.Equal(t, 2, apiV1.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, apiV1.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, apiV1.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, apiV1.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, apiV1.Resources[0].Methods[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 17, apiV1.Resources[0].Methods[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 14, apiV1.Resources[0].Methods[0].HTTPMethod.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, apiV1.Resources[0].Methods[0].HTTPMethod.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, apiV1.Resources[0].Methods[0].AuthorizationType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, apiV1.Resources[0].Methods[0].AuthorizationType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, apiV1.Resources[0].Methods[0].APIKeyRequired.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, apiV1.Resources[0].Methods[0].APIKeyRequired.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, apiV2.Metadata.Range().GetStartLine())
	assert.Equal(t, 22, apiV2.Metadata.Range().GetEndLine())

	assert.Equal(t, 20, apiV2.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, apiV2.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, apiV2.ProtocolType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, apiV2.ProtocolType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 24, apiV2.Stages[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 30, apiV2.Stages[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 26, apiV2.Stages[0].Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 26, apiV2.Stages[0].Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 27, apiV2.Stages[0].AccessLogging.Metadata.Range().GetStartLine())
	assert.Equal(t, 29, apiV2.Stages[0].AccessLogging.Metadata.Range().GetEndLine())

	assert.Equal(t, 28, apiV2.Stages[0].AccessLogging.CloudwatchLogGroupARN.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, apiV2.Stages[0].AccessLogging.CloudwatchLogGroupARN.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 32, domainName.Metadata.Range().GetStartLine())
	assert.Equal(t, 35, domainName.Metadata.Range().GetEndLine())

	assert.Equal(t, 33, domainName.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 33, domainName.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 34, domainName.SecurityPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, domainName.SecurityPolicy.GetMetadata().Range().GetEndLine())

}
