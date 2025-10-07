package eks

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
			API:               iacTypes.BoolDefault(false, resource.GetMetadata()),
			Audit:             iacTypes.BoolDefault(false, resource.GetMetadata()),
			Authenticator:     iacTypes.BoolDefault(false, resource.GetMetadata()),
			ControllerManager: iacTypes.BoolDefault(false, resource.GetMetadata()),
			Scheduler:         iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		Encryption: eks.Encryption{
			Metadata: resource.GetMetadata(),
			Secrets:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: iacTypes.StringDefault("", resource.GetMetadata()),
		},
		PublicAccessEnabled: iacTypes.BoolDefault(true, resource.GetMetadata()),
		PublicAccessCIDRs:   nil,
	}

	if logTypesAttr := resource.GetAttribute("enabled_cluster_log_types"); logTypesAttr.IsNotNil() {
		cluster.Logging.Metadata = logTypesAttr.GetMetadata()
		for _, logType := range logTypesAttr.AsStringValues() {
			switch logType.Value() {
			case "api":
				cluster.Logging.API = iacTypes.Bool(true, logTypesAttr.GetMetadata())
			case "audit":
				cluster.Logging.Audit = iacTypes.Bool(true, logTypesAttr.GetMetadata())
			case "authenticator":
				cluster.Logging.Authenticator = iacTypes.Bool(true, logTypesAttr.GetMetadata())
			case "controllerManager":
				cluster.Logging.ControllerManager = iacTypes.Bool(true, logTypesAttr.GetMetadata())
			case "scheduler":
				cluster.Logging.Scheduler = iacTypes.Bool(true, logTypesAttr.GetMetadata())
			}
		}
	}

	if encryptBlock := resource.GetBlock("encryption_config"); encryptBlock.IsNotNil() {
		cluster.Encryption.Metadata = encryptBlock.GetMetadata()
		resourcesAttr := encryptBlock.GetAttribute("resources")
		if resourcesAttr.Contains("secrets") {
			cluster.Encryption.Secrets = iacTypes.Bool(true, resourcesAttr.GetMetadata())
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
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, iacTypes.StringDefault("0.0.0.0/0", vpcBlock.GetMetadata()))
		}
	}

	return cluster
}
