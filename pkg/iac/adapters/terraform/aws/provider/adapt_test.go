package provider

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected []aws.TerraformProvider
	}{
		{
			name: "happy",
			source: `
variable "s3_use_path_style" {
	default = true
}

provider "aws" {
  version = "~> 5.0"
  region  = "us-east-1"
  profile = "localstack"

  access_key                  = "fake"
  secret_key                  = "fake"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style         = var.s3_use_path_style

  endpoints {
    dynamodb   = "http://localhost:4566"
    s3         = "http://localhost:4566"
  }

  default_tags {
    tags = {
      Environment = "Local"
      Name        = "LocalStack"
    }
  }
}`,
			expected: []aws.TerraformProvider{
				{
					Version: types.StringTest("~> 5.0"),
					Region:  types.StringTest("us-east-1"),
					DefaultTags: aws.DefaultTags{
						Tags: types.MapTest(map[string]string{
							"Environment": "Local",
							"Name":        "LocalStack",
						}),
					},
					Endpoints: types.MapTest(map[string]string{
						"dynamodb": "http://localhost:4566",
						"s3":       "http://localhost:4566",
					}),
					Profile:                   types.StringTest("localstack"),
					AccessKey:                 types.StringTest("fake"),
					SecretKey:                 types.StringTest("fake"),
					SkipCredentialsValidation: types.BoolTest(true),
					SkipMetadataAPICheck:      types.BoolTest(true),
					SkipRequestingAccountID:   types.BoolTest(true),
					S3UsePathStyle:            types.BoolTest(true),
					MaxRetries:                types.IntTest(defaultMaxRetires),
					SharedConfigFiles: types.StringValueList{
						types.StringTest(defaultSharedConfigFile),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringTest(defaultSharedCredentialsFile),
					},
				},
			},
		},
		{
			name: "multiply provider configurations",
			source: `

provider "aws" {
	region = "us-east-1"
}

provider "aws" {
  alias  = "west"
  region = "us-west-2"
}
`,
			expected: []aws.TerraformProvider{
				{
					Region:     types.StringTest("us-east-1"),
					Endpoints:  types.MapTest(make(map[string]string)),
					MaxRetries: types.IntTest(defaultMaxRetires),
					SharedConfigFiles: types.StringValueList{
						types.StringTest(defaultSharedConfigFile),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringTest(defaultSharedCredentialsFile),
					},
				},
				{
					Alias:      types.StringTest("west"),
					Region:     types.StringTest("us-west-2"),
					Endpoints:  types.MapTest(make(map[string]string)),
					MaxRetries: types.IntTest(defaultMaxRetires),
					SharedConfigFiles: types.StringValueList{
						types.StringTest(defaultSharedConfigFile),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringTest(defaultSharedCredentialsFile),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.source, ".tf")
			testutil.AssertDefsecEqual(t, test.expected, Adapt(modules))
		})
	}
}
