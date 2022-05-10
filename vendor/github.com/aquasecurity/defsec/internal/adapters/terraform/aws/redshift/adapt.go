package redshift

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) redshift.Redshift {
	return redshift.Redshift{
		Clusters:       adaptClusters(modules),
		SecurityGroups: adaptSecurityGroups(modules),
	}
}

func adaptClusters(modules terraform.Modules) []redshift.Cluster {
	var clusters []redshift.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}
	return clusters
}

func adaptSecurityGroups(modules terraform.Modules) []redshift.SecurityGroup {
	var securityGroups []redshift.SecurityGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_security_group") {
			securityGroups = append(securityGroups, adaptSecurityGroup(resource))
		}
	}
	return securityGroups
}

func adaptCluster(resource *terraform.Block, module *terraform.Module) redshift.Cluster {
	cluster := redshift.Cluster{
		Metadata: resource.GetMetadata(),
		Encryption: redshift.Encryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: types.StringDefault("", resource.GetMetadata()),
		},
		SubnetGroupName: types.StringDefault("", resource.GetMetadata()),
	}

	encryptedAttr := resource.GetAttribute("encrypted")
	cluster.Encryption.Enabled = encryptedAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	cluster.Encryption.KMSKeyID = KMSKeyIDAttr.AsStringValueOrDefault("", resource)
	if KMSKeyIDAttr.IsResourceBlockReference("aws_kms_key") {
		if kmsKeyBlock, err := module.GetReferencedBlock(KMSKeyIDAttr, resource); err == nil {
			cluster.Encryption.KMSKeyID = types.String(kmsKeyBlock.FullName(), kmsKeyBlock.GetMetadata())
		}
	}

	subnetGroupNameAttr := resource.GetAttribute("cluster_subnet_group_name")
	cluster.SubnetGroupName = subnetGroupNameAttr.AsStringValueOrDefault("", resource)

	return cluster
}

func adaptSecurityGroup(resource *terraform.Block) redshift.SecurityGroup {
	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	return redshift.SecurityGroup{
		Metadata:    resource.GetMetadata(),
		Description: descriptionVal,
	}
}
