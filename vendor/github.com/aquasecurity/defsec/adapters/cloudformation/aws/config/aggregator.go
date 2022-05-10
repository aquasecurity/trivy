package config

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/config"
)

func getConfiguraionAggregator(ctx parser.FileContext) (aggregator config.ConfigurationAggregrator) {

	aggregatorResources := ctx.GetResourceByType("AWS::Config::ConfigurationAggregator")

	if len(aggregatorResources) == 0 {
		return config.ConfigurationAggregrator{
			SourceAllRegions: types.BoolDefault(false, ctx.Metadata()),
		}
	}

	return config.ConfigurationAggregrator{
		IsDefined:        true,
		SourceAllRegions: isSourcingAllRegions(aggregatorResources[0]),
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
