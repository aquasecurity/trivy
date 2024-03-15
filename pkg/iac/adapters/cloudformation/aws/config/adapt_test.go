package config

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/config"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected config.Config
	}{
		{
			name: "Config aggregator with AccountAggregationSources",
			source: `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  ConfigurationAggregator:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      AccountAggregationSources:
        - AllAwsRegions: "true"
`,
			expected: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					SourceAllRegions: types.BoolTest(true),
				},
			},
		},
		{
			name: "Config aggregator with OrganizationAggregationSource",
			source: `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  ConfigurationAggregator:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      OrganizationAggregationSource:
        AllAwsRegions: "true"
`,
			expected: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					SourceAllRegions: types.BoolTest(true),
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
