package provider

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/providers/aws"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
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
					Version: types.String("~> 5.0", types.NewTestMisconfigMetadata()),
					Region:  types.String("us-east-1", types.NewTestMisconfigMetadata()),
					DefaultTags: aws.DefaultTags{
						Metadata: types.NewTestMisconfigMetadata(),
						Tags: types.Map(map[string]string{
							"Environment": "Local",
							"Name":        "LocalStack",
						}, types.NewTestMisconfigMetadata()),
					},
					Endpoints: types.Map(map[string]string{
						"dynamodb": "http://localhost:4566",
						"s3":       "http://localhost:4566",
					}, types.NewTestMisconfigMetadata()),
					Profile:                   types.String("localstack", types.NewTestMisconfigMetadata()),
					AccessKey:                 types.String("fake", types.NewTestMisconfigMetadata()),
					SecretKey:                 types.String("fake", types.NewTestMisconfigMetadata()),
					SkipCredentialsValidation: types.Bool(true, types.NewTestMisconfigMetadata()),
					SkipMetadataAPICheck:      types.Bool(true, types.NewTestMisconfigMetadata()),
					SkipRequestingAccountID:   types.Bool(true, types.NewTestMisconfigMetadata()),
					S3UsePathStyle:            types.Bool(true, types.NewTestMisconfigMetadata()),
					MaxRetries:                types.IntDefault(defaultMaxRetires, types.NewTestMisconfigMetadata()),
					SharedConfigFiles: types.StringValueList{
						types.StringDefault(defaultSharedConfigFile, types.NewTestMisconfigMetadata()),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringDefault(defaultSharedCredentialsFile, types.NewTestMisconfigMetadata()),
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
					Region:     types.String("us-east-1", types.NewTestMisconfigMetadata()),
					Endpoints:  types.Map(make(map[string]string), types.NewTestMisconfigMetadata()),
					MaxRetries: types.IntDefault(defaultMaxRetires, types.NewTestMisconfigMetadata()),
					SharedConfigFiles: types.StringValueList{
						types.StringDefault(defaultSharedConfigFile, types.NewTestMisconfigMetadata()),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringDefault(defaultSharedCredentialsFile, types.NewTestMisconfigMetadata()),
					},
				},
				{
					Alias:      types.String("west", types.NewTestMisconfigMetadata()),
					Region:     types.String("us-west-2", types.NewTestMisconfigMetadata()),
					Endpoints:  types.Map(make(map[string]string), types.NewTestMisconfigMetadata()),
					MaxRetries: types.IntDefault(defaultMaxRetires, types.NewTestMisconfigMetadata()),
					SharedConfigFiles: types.StringValueList{
						types.StringDefault(defaultSharedConfigFile, types.NewTestMisconfigMetadata()),
					},
					SharedCredentialsFiles: types.StringValueList{
						types.StringDefault(defaultSharedCredentialsFile, types.NewTestMisconfigMetadata()),
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
