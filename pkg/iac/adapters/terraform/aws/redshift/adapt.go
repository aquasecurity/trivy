package redshift

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) redshift.Redshift {
	return redshift.Redshift{
		Clusters:          adaptClusters(modules),
		SecurityGroups:    adaptSecurityGroups(modules),
		ClusterParameters: adaptParameters(modules),
		ReservedNodes:     nil,
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

func adaptParameters(modules terraform.Modules) []redshift.ClusterParameter {
	var Parameters []redshift.ClusterParameter
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_parameter_group") {
			for _, r := range resource.GetBlocks("parameter") {
				Parameters = append(Parameters, adaptParameter(r))
			}
		}
	}
	return Parameters
}

func adaptCluster(resource *terraform.Block, module *terraform.Module) redshift.Cluster {
	cluster := redshift.Cluster{
		Metadata:                         resource.GetMetadata(),
		ClusterIdentifier:                resource.GetAttribute("cluster_identifier").AsStringValue(),
		NodeType:                         resource.GetAttribute("node_type").AsStringValue(),
		MasterUsername:                   resource.GetAttribute("master_username").AsStringValue(),
		NumberOfNodes:                    resource.GetAttribute("number_of_nodes").AsIntValue(1),
		PubliclyAccessible:               resource.GetAttribute("publicly_accessible").AsBoolValue(true),
		LoggingEnabled:                   iacTypes.Bool(false, resource.GetMetadata()),
		AutomatedSnapshotRetentionPeriod: iacTypes.Int(0, resource.GetMetadata()),
		AllowVersionUpgrade:              resource.GetAttribute("allow_version_upgrade").AsBoolValue(true),
		VpcId:                            iacTypes.String("", resource.GetMetadata()),
		Encryption: redshift.Encryption{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: iacTypes.StringDefault("", resource.GetMetadata()),
		},
		EndPoint: redshift.EndPoint{
			Metadata: resource.GetMetadata(),
			Port:     resource.GetAttribute("port").AsIntValue(5439),
		},
		SubnetGroupName: iacTypes.StringDefault("", resource.GetMetadata()),
	}

	encryptedAttr := resource.GetAttribute("encrypted")
	cluster.Encryption.Enabled = encryptedAttr.AsBoolValue()

	if logBlock := resource.GetBlock("logging"); logBlock.IsNotNil() {
		cluster.LoggingEnabled = logBlock.GetAttribute("enable").AsBoolValue()
	}

	if snapBlock := resource.GetBlock("snapshot_copy"); snapBlock.IsNotNil() {
		snapAttr := snapBlock.GetAttribute("retention_period")
		cluster.AutomatedSnapshotRetentionPeriod = snapAttr.AsIntValue(7)
	}

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	cluster.Encryption.KMSKeyID = KMSKeyIDAttr.AsStringValue()
	if KMSKeyIDAttr.IsResourceBlockReference("aws_kms_key") {
		if kmsKeyBlock, err := module.GetReferencedBlock(KMSKeyIDAttr, resource); err == nil {
			cluster.Encryption.KMSKeyID = iacTypes.String(kmsKeyBlock.FullName(), kmsKeyBlock.GetMetadata())
		}
	}

	subnetGroupNameAttr := resource.GetAttribute("cluster_subnet_group_name")
	cluster.SubnetGroupName = subnetGroupNameAttr.AsStringValue()

	return cluster
}

func adaptSecurityGroup(resource *terraform.Block) redshift.SecurityGroup {
	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValue("Managed by Terraform")

	return redshift.SecurityGroup{
		Metadata:    resource.GetMetadata(),
		Description: descriptionVal,
	}
}

func adaptParameter(resource *terraform.Block) redshift.ClusterParameter {

	return redshift.ClusterParameter{
		Metadata:       resource.GetMetadata(),
		ParameterName:  resource.GetAttribute("name").AsStringValue(),
		ParameterValue: resource.GetAttribute("value").AsStringValue(),
	}
}
