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
					Version: types.String("~> 5.0", types.NewTestMetadata()),
					Region:  types.String("us-east-1", types.NewTestMetadata()),
					DefaultTags: aws.DefaultTags{
						Metadata: types.NewTestMetadata(),
						Tags: types.Map(map[string]string{
							"Environment": "Local",
							"Name":        "LocalStack",
						}, types.NewTestMetadata()),
					},
					Endpoints: types.Map(map[string]string{
						"dynamodb": "http://localhost:4566",
						"s3":       "http://localhost:4566",
					}, types.NewTestMetadata()),
					Profile:                   types.String("localstack", types.NewTestMetadata()),
					AccessKey:                 types.String("fake", types.NewTestMetadata()),
					SecretKey:                 types.String("fake", types.NewTestMetadata()),
					SkipCredentialsValidation: types.Bool(true, types.NewTestMetadata()),
					SkipMetadataAPICheck:      types.Bool(true, types.NewTestMetadata()),
					SkipRequestingAccountID:   types.Bool(true, types.NewTestMetadata()),
					S3UsePathStyle:            types.Bool(true, types.NewTestMetadata()),
					MaxRetries:                types.IntDefault(defaultMaxRetires, types.NewTestMetadata()),
					SharedConfigFiles: types.StringValueList{
						types.StringDefault(defaultSharedConfigFile, types.NewTestMetadata()),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringDefault(defaultSharedCredentialsFile, types.NewTestMetadata()),
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
					Region:     types.String("us-east-1", types.NewTestMetadata()),
					Endpoints:  types.Map(make(map[string]string), types.NewTestMetadata()),
					MaxRetries: types.IntDefault(defaultMaxRetires, types.NewTestMetadata()),
					SharedConfigFiles: types.StringValueList{
						types.StringDefault(defaultSharedConfigFile, types.NewTestMetadata()),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringDefault(defaultSharedCredentialsFile, types.NewTestMetadata()),
					},
				},
				{
					Alias:      types.String("west", types.NewTestMetadata()),
					Region:     types.String("us-west-2", types.NewTestMetadata()),
					Endpoints:  types.Map(make(map[string]string), types.NewTestMetadata()),
					MaxRetries: types.IntDefault(defaultMaxRetires, types.NewTestMetadata()),
					SharedConfigFiles: types.StringValueList{
						types.StringDefault(defaultSharedConfigFile, types.NewTestMetadata()),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringDefault(defaultSharedCredentialsFile, types.NewTestMetadata()),
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
