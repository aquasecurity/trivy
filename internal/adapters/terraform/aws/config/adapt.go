package config

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) config.Config {
	return config.Config{
		ConfigurationAggregrator: adaptConfigurationAggregrator(modules),
	}
}

func adaptConfigurationAggregrator(modules terraform.Modules) config.ConfigurationAggregrator {
	configurationAggregrator := config.ConfigurationAggregrator{
		Metadata:         defsecTypes.NewUnmanagedMetadata(),
		SourceAllRegions: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
	}

	for _, resource := range modules.GetResourcesByType("aws_config_configuration_aggregator") {
		configurationAggregrator.Metadata = resource.GetMetadata()
		aggregationBlock := resource.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
		if aggregationBlock.IsNil() {
			configurationAggregrator.SourceAllRegions = defsecTypes.Bool(false, resource.GetMetadata())
		} else {
			allRegionsAttr := aggregationBlock.GetAttribute("all_regions")
			allRegionsVal := allRegionsAttr.AsBoolValueOrDefault(false, aggregationBlock)
			configurationAggregrator.SourceAllRegions = allRegionsVal
		}
	}
	return configurationAggregrator
}
