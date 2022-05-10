package config

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) config.Config {
	return config.Config{
		ConfigurationAggregrator: adaptConfigurationAggregrator(modules),
	}
}

func adaptConfigurationAggregrator(modules terraform.Modules) config.ConfigurationAggregrator {
	configurationAggregrator := config.ConfigurationAggregrator{
		Metadata:         types.NewUnmanagedMetadata(),
		SourceAllRegions: types.BoolDefault(false, types.NewUnmanagedMetadata()),
		IsDefined:        false,
	}

	for _, resource := range modules.GetResourcesByType("aws_config_configuration_aggregator") {
		configurationAggregrator.Metadata = resource.GetMetadata()
		configurationAggregrator.IsDefined = true

		aggregationBlock := resource.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
		if aggregationBlock.IsNil() {
			configurationAggregrator.SourceAllRegions = types.Bool(false, resource.GetMetadata())
		} else {
			allRegionsAttr := aggregationBlock.GetAttribute("all_regions")
			allRegionsVal := allRegionsAttr.AsBoolValueOrDefault(false, aggregationBlock)
			configurationAggregrator.SourceAllRegions = allRegionsVal
		}
	}
	return configurationAggregrator
}
