package monitor

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(deployment azure.Deployment) monitor.Monitor {
	return monitor.Monitor{
		LogProfiles: adaptLogProfiles(deployment),
	}
}

func adaptLogProfiles(deployment azure.Deployment) (logProfiles []monitor.LogProfile) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Insights/logProfiles") {
		logProfiles = append(logProfiles, adaptLogProfile(resource))
	}
	return logProfiles
}

func adaptLogProfile(resource azure.Resource) monitor.LogProfile {
	categories := resource.Properties.GetMapValue("categories").AsList()
	var categoriesList []types.StringValue
	for _, category := range categories {
		categoriesList = append(categoriesList, category.AsStringValue("", category.Metadata))
	}

	locations := resource.Properties.GetMapValue("locations").AsList()
	var locationsList []types.StringValue
	for _, location := range locations {
		locationsList = append(locationsList, location.AsStringValue("", location.Metadata))
	}

	return monitor.LogProfile{
		Metadata: resource.Metadata,
		RetentionPolicy: monitor.RetentionPolicy{
			Metadata: resource.Metadata,
			Enabled:  resource.Properties.GetMapValue("retentionPolicy").GetMapValue("enabled").AsBoolValue(false, resource.Metadata),
			Days:     resource.Properties.GetMapValue("retentionPolicy").GetMapValue("days").AsIntValue(0, resource.Metadata),
		},
		Categories: categoriesList,
		Locations:  locationsList,
	}
}
