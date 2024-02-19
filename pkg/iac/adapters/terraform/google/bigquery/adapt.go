package bigquery

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/bigquery"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) bigquery.BigQuery {
	return bigquery.BigQuery{
		Datasets: adaptDatasets(modules),
	}
}

func adaptDatasets(modules terraform.Modules) []bigquery.Dataset {
	var datasets []bigquery.Dataset
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_bigquery_dataset") {
			datasets = append(datasets, adaptDataset(resource))
		}
	}
	return datasets
}

func adaptDataset(resource *terraform.Block) bigquery.Dataset {
	IDAttr := resource.GetAttribute("dataset_id")
	IDVal := IDAttr.AsStringValueOrDefault("", resource)

	var accessGrants []bigquery.AccessGrant

	accessBlocks := resource.GetBlocks("access")
	for _, accessBlock := range accessBlocks {
		roleAttr := accessBlock.GetAttribute("role")
		roleVal := roleAttr.AsStringValueOrDefault("", accessBlock)

		domainAttr := accessBlock.GetAttribute("domain")
		domainVal := domainAttr.AsStringValueOrDefault("", accessBlock)

		specialGrAttr := accessBlock.GetAttribute("special_group")
		specialGrVal := specialGrAttr.AsStringValueOrDefault("", accessBlock)

		accessGrants = append(accessGrants, bigquery.AccessGrant{
			Metadata:     accessBlock.GetMetadata(),
			Role:         roleVal,
			Domain:       domainVal,
			SpecialGroup: specialGrVal,
		})
	}

	return bigquery.Dataset{
		Metadata:     resource.GetMetadata(),
		ID:           IDVal,
		AccessGrants: accessGrants,
	}
}
