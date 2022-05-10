package config

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getConfiguraionAggregator(ctx parser.FileContext) (aggregator config.ConfigurationAggregrator) {

	aggregatorResources := ctx.GetResourcesByType("AWS::Config::ConfigurationAggregator")

	if len(aggregatorResources) == 0 {
		return config.ConfigurationAggregrator{
			Metadata:         types.NewUnmanagedMetadata(),
			SourceAllRegions: types.BoolDefault(false, ctx.Metadata()),
			IsDefined:        false,
		}
	}

	return config.ConfigurationAggregrator{
		Metadata:         aggregatorResources[0].Metadata(),
		SourceAllRegions: isSourcingAllRegions(aggregatorResources[0]),
		IsDefined:        true,
	}
}

func isSourcingAllRegions(r *parser.Resource) types.BoolValue {
	accountProp := r.GetProperty("AccountAggregationSources")
	orgProp := r.GetProperty("OrganizationAggregationSource")

	if accountProp.IsNotNil() && accountProp.IsList() {
		for _, a := range accountProp.AsList() {
			regionsProp := a.GetProperty("AllAwsRegions")
			if regionsProp.IsNil() || regionsProp.IsBool() {
				return regionsProp.AsBoolValue()
			}
		}
	}

	if orgProp.IsNotNil() {
		regionsProp := orgProp.GetProperty("AllAwsRegions")
		if regionsProp.IsBool() {
			return regionsProp.AsBoolValue()
		}
	}

	// nothing is set or resolvable so its got to be false
	return types.BoolDefault(false, r.Metadata())
}
