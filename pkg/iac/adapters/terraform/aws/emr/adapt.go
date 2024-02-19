package emr

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/emr"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) emr.EMR {
	return emr.EMR{
		Clusters:              adaptClusters(modules),
		SecurityConfiguration: adaptSecurityConfigurations(modules),
	}
}
func adaptClusters(modules terraform.Modules) []emr.Cluster {
	var clusters []emr.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_emr_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block) emr.Cluster {

	return emr.Cluster{
		Metadata: resource.GetMetadata(),
	}
}

func adaptSecurityConfigurations(modules terraform.Modules) []emr.SecurityConfiguration {
	var securityConfiguration []emr.SecurityConfiguration
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_emr_security_configuration") {
			securityConfiguration = append(securityConfiguration, adaptSecurityConfiguration(resource))
		}
	}
	return securityConfiguration
}

func adaptSecurityConfiguration(resource *terraform.Block) emr.SecurityConfiguration {

	return emr.SecurityConfiguration{
		Metadata:      resource.GetMetadata(),
		Name:          resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Configuration: resource.GetAttribute("configuration").AsStringValueOrDefault("", resource),
	}

}
