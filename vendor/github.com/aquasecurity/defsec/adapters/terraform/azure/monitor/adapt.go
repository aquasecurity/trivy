package monitor

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/monitor"
)

func Adapt(modules terraform.Modules) monitor.Monitor {
	return monitor.Monitor{
		LogProfiles: adaptLogProfiles(modules),
	}
}

func adaptLogProfiles(modules terraform.Modules) []monitor.LogProfile {
	var logProfiles []monitor.LogProfile

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_monitor_log_profile") {
			logProfiles = append(logProfiles, adaptLogProfile(resource))
		}
	}
	return logProfiles
}

func adaptLogProfile(resource *terraform.Block) monitor.LogProfile {

	logProfile := monitor.LogProfile{
		Metadata: resource.GetMetadata(),
		RetentionPolicy: monitor.RetentionPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			Days:     types.IntDefault(0, resource.GetMetadata()),
		},
	}

	if retentionPolicyBlock := resource.GetBlock("retention_policy"); retentionPolicyBlock.IsNotNil() {
		logProfile.RetentionPolicy.Metadata = retentionPolicyBlock.GetMetadata()
		enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
		logProfile.RetentionPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, resource)
		daysAttr := retentionPolicyBlock.GetAttribute("days")
		logProfile.RetentionPolicy.Days = daysAttr.AsIntValueOrDefault(0, resource)
	}

	if categoriesAttr := resource.GetAttribute("categories"); categoriesAttr.IsNotNil() {
		for _, category := range categoriesAttr.ValueAsStrings() {
			logProfile.Categories = append(logProfile.Categories, types.String(category, resource.GetMetadata()))
		}
	}

	if locationsAttr := resource.GetAttribute("locations"); locationsAttr.IsNotNil() {
		for _, location := range locationsAttr.ValueAsStrings() {
			logProfile.Locations = append(logProfile.Locations, types.String(location, resource.GetMetadata()))
		}
	}

	return logProfile
}
