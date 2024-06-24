package apigateway

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	v2 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v2"
)

func Test_adaptAPIsV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []v2.API
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_apigatewayv2_api" "example" {
    protocol_type = "HTTP"
}
`,
			expected: []v2.API{
				{
					Name:         String(""),
					ProtocolType: String("HTTP"),
				},
			},
		},
		{
			name: "full",
			terraform: `
resource "aws_apigatewayv2_api" "example" {
    name = "tfsec"
    protocol_type = "HTTP"
}
`,
			expected: []v2.API{
				{
					Name:         String("tfsec"),
					ProtocolType: String("HTTP"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptAPIsV2(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptStageV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  v2.Stage
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_apigatewayv2_stage" "example" {
    
}
`,
			expected: v2.Stage{
				Name: String(""),
				AccessLogging: v2.AccessLogging{
					CloudwatchLogGroupARN: String(""),
				},
			},
		},
		{
			name: "basics",
			terraform: `
resource "aws_apigatewayv2_stage" "example" {
    name = "tfsec" 
    access_log_settings {
        destination_arn = "arn:123"
    }
}
`,
			expected: v2.Stage{
				Name: String("tfsec"),
				AccessLogging: v2.AccessLogging{
					CloudwatchLogGroupARN: String("arn:123"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptStageV2(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
