package config

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/config"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getConfigurationAggregator(ctx parser2.FileContext) config.ConfigurationAggregrator {

	aggregator := config.ConfigurationAggregrator{
		Metadata:         iacTypes.NewUnmanagedMetadata(),
		SourceAllRegions: iacTypes.BoolDefault(false, ctx.Metadata()),
	}

	aggregatorResources := ctx.GetResourcesByType("AWS::Config::ConfigurationAggregator")

	if len(aggregatorResources) == 0 {
		return aggregator
	}

	return config.ConfigurationAggregrator{
		Metadata:         aggregatorResources[0].Metadata(),
		SourceAllRegions: isSourcingAllRegions(aggregatorResources[0]),
	}
}

func isSourcingAllRegions(r *parser2.Resource) iacTypes.BoolValue {
	accountProp := r.GetProperty("AccountAggregationSources")

	if accountProp.IsNotNil() && accountProp.IsList() {
		for _, a := range accountProp.AsList() {
			regionsProp := a.GetProperty("AllAwsRegions")
			if regionsProp.IsNotNil() {
				return a.GetBoolProperty("AllAwsRegions")
			}
		}
	}

	return r.GetBoolProperty("OrganizationAggregationSource.AllAwsRegions")
}
