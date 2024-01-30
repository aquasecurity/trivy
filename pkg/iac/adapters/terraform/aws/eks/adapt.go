package eks

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) eks.EKS {
	return eks.EKS{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []eks.Cluster {
	var clusters []eks.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_eks_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block) eks.Cluster {

	cluster := eks.Cluster{
		Metadata: resource.GetMetadata(),
		Logging: eks.Logging{
			Metadata:          resource.GetMetadata(),
			API:               defsecTypes.BoolDefault(false, resource.GetMetadata()),
			Audit:             defsecTypes.BoolDefault(false, resource.GetMetadata()),
			Authenticator:     defsecTypes.BoolDefault(false, resource.GetMetadata()),
			ControllerManager: defsecTypes.BoolDefault(false, resource.GetMetadata()),
			Scheduler:         defsecTypes.BoolDefault(false, resource.GetMetadata()),
		},
		Encryption: eks.Encryption{
			Metadata: resource.GetMetadata(),
			Secrets:  defsecTypes.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: defsecTypes.StringDefault("", resource.GetMetadata()),
		},
		PublicAccessEnabled: defsecTypes.BoolDefault(true, resource.GetMetadata()),
		PublicAccessCIDRs:   nil,
	}

	if logTypesAttr := resource.GetAttribute("enabled_cluster_log_types"); logTypesAttr.IsNotNil() {
		cluster.Logging.Metadata = logTypesAttr.GetMetadata()
		for _, logType := range logTypesAttr.AsStringValues() {
			switch logType.Value() {
			case "api":
				cluster.Logging.API = defsecTypes.Bool(true, logTypesAttr.GetMetadata())
			case "audit":
				cluster.Logging.Audit = defsecTypes.Bool(true, logTypesAttr.GetMetadata())
			case "authenticator":
				cluster.Logging.Authenticator = defsecTypes.Bool(true, logTypesAttr.GetMetadata())
			case "controllerManager":
				cluster.Logging.ControllerManager = defsecTypes.Bool(true, logTypesAttr.GetMetadata())
			case "scheduler":
				cluster.Logging.Scheduler = defsecTypes.Bool(true, logTypesAttr.GetMetadata())
			}
		}
	}

	if encryptBlock := resource.GetBlock("encryption_config"); encryptBlock.IsNotNil() {
		cluster.Encryption.Metadata = encryptBlock.GetMetadata()
		resourcesAttr := encryptBlock.GetAttribute("resources")
		if resourcesAttr.Contains("secrets") {
			cluster.Encryption.Secrets = defsecTypes.Bool(true, resourcesAttr.GetMetadata())
		}
		if providerBlock := encryptBlock.GetBlock("provider"); providerBlock.IsNotNil() {
			keyArnAttr := providerBlock.GetAttribute("key_arn")
			cluster.Encryption.KMSKeyID = keyArnAttr.AsStringValueOrDefault("", providerBlock)
		}
	}

	if vpcBlock := resource.GetBlock("vpc_config"); vpcBlock.IsNotNil() {
		publicAccessAttr := vpcBlock.GetAttribute("endpoint_public_access")
		cluster.PublicAccessEnabled = publicAccessAttr.AsBoolValueOrDefault(true, vpcBlock)

		publicAccessCidrsAttr := vpcBlock.GetAttribute("public_access_cidrs")
		cidrList := publicAccessCidrsAttr.AsStringValues()
		for _, cidr := range cidrList {
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, cidr)
		}
		if len(cidrList) == 0 {
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, defsecTypes.StringDefault("0.0.0.0/0", vpcBlock.GetMetadata()))
		}
	}

	return cluster
}
