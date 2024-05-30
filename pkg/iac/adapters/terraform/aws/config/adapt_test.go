package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/config"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptConfigurationAggregrator(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  config.ConfigurationAggregrator
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_config_configuration_aggregator" "example" {
				name = "example"
				  
				account_aggregation_source {
				  account_ids = ["123456789012"]
				  all_regions = true
				}
			}
`,
			expected: config.ConfigurationAggregrator{
				Metadata:         iacTypes.NewTestMetadata(),
				SourceAllRegions: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_config_configuration_aggregator" "example" {
			}
`,
			expected: config.ConfigurationAggregrator{
				Metadata:         iacTypes.NewTestMetadata(),
				SourceAllRegions: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptConfigurationAggregrator(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_config_configuration_aggregator" "example" {
		name = "example"
		  
		account_aggregation_source {
		  account_ids = ["123456789012"]
		  all_regions = true
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)
	aggregator := adapted.ConfigurationAggregrator

	assert.Equal(t, 2, aggregator.Metadata.Range().GetStartLine())
	assert.Equal(t, 9, aggregator.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, aggregator.SourceAllRegions.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, aggregator.SourceAllRegions.GetMetadata().Range().GetEndLine())
}
