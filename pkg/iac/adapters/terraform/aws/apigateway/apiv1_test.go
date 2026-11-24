package apigateway

import (
	"net/http"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
)

func Test_adaptAPIMethodsV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []v1.Method
	}{
		{
			name: "defaults",
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
`,
			expected: []v1.Method{
				{
					HTTPMethod:        String(http.MethodGet),
					AuthorizationType: String("NONE"),
					APIKeyRequired:    Bool(false),
				},
			},
		},
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
    api_key_required = true
}
`,
			expected: []v1.Method{
				{
					HTTPMethod:        String(http.MethodGet),
					AuthorizationType: String("NONE"),
					APIKeyRequired:    Bool(true),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			restApiBlock := modules.GetBlocks()[1]
			adapted := adaptAPIMethodsV1(modules, restApiBlock)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptAPIsV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []v1.API
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_api_gateway_rest_api" "example" {
    
}
`,
			expected: []v1.API{
				{
					Name: String(""),
				},
			},
		},
		{
			name: "full",
			terraform: `
resource "aws_api_gateway_rest_api" "example" {
   name = "tfsec" 
}
`,
			expected: []v1.API{
				{
					Name: String("tfsec"),
				},
			},
		},
		{
			name: "root and child methods",
			terraform: `
resource "aws_api_gateway_rest_api" "api" {
  name = "demo"
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "root_any" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_rest_api.api.root_resource_id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "proxy_any" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "AWS_IAM"
}
`,
			expected: []v1.API{
				{
					Name: String("demo"),
					Resources: []v1.Resource{
						{
							Methods: []v1.Method{
								{
									HTTPMethod:        String("ANY"),
									AuthorizationType: String("NONE"),
									APIKeyRequired:    Bool(false),
								},
							},
						},
						{
							Methods: []v1.Method{
								{
									HTTPMethod:        String("ANY"),
									AuthorizationType: String("AWS_IAM"),
									APIKeyRequired:    Bool(false),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "root method only",
			terraform: `
resource "aws_api_gateway_rest_api" "api" {
  name = "demo"
}

resource "aws_api_gateway_method" "root_get" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_rest_api.api.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
}
`,
			expected: []v1.API{
				{
					Name: String("demo"),
					Resources: []v1.Resource{
						{
							Methods: []v1.Method{
								{
									HTTPMethod:        String("GET"),
									AuthorizationType: String("NONE"),
									APIKeyRequired:    Bool(false),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptAPIsV1(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
