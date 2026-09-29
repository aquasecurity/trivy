package monitor

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			Days:     iacTypes.IntDefault(0, resource.GetMetadata()),
		},
		Categories: nil,
		Locations:  nil,
	}

	if retentionPolicyBlock := resource.GetBlock("retention_policy"); retentionPolicyBlock.IsNotNil() {
		logProfile.RetentionPolicy.Metadata = retentionPolicyBlock.GetMetadata()
		enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
		logProfile.RetentionPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, resource)
		daysAttr := retentionPolicyBlock.GetAttribute("days")
		logProfile.RetentionPolicy.Days = daysAttr.AsIntValueOrDefault(0, resource)
	}

	if categoriesAttr := resource.GetAttribute("categories"); categoriesAttr.IsNotNil() {
		logProfile.Categories = categoriesAttr.AsStringValues()
	}

	if locationsAttr := resource.GetAttribute("locations"); locationsAttr.IsNotNil() {
		logProfile.Locations = locationsAttr.AsStringValues()
	}

	return logProfile
}
