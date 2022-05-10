package eks

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/terraform"
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
			API:               types.BoolDefault(false, resource.GetMetadata()),
			Audit:             types.BoolDefault(false, resource.GetMetadata()),
			Authenticator:     types.BoolDefault(false, resource.GetMetadata()),
			ControllerManager: types.BoolDefault(false, resource.GetMetadata()),
			Scheduler:         types.BoolDefault(false, resource.GetMetadata()),
		},
		Encryption: eks.Encryption{
			Metadata: resource.GetMetadata(),
			Secrets:  types.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: types.StringDefault("", resource.GetMetadata()),
		},
		PublicAccessEnabled: types.BoolDefault(true, resource.GetMetadata()),
		PublicAccessCIDRs:   nil,
	}

	if logTypesAttr := resource.GetAttribute("enabled_cluster_log_types"); logTypesAttr.IsNotNil() {
		cluster.Logging.Metadata = logTypesAttr.GetMetadata()
		logTypesList := logTypesAttr.ValueAsStrings()
		for _, logType := range logTypesList {
			switch logType {
			case "api":
				cluster.Logging.API = types.Bool(true, logTypesAttr.GetMetadata())
			case "audit":
				cluster.Logging.Audit = types.Bool(true, logTypesAttr.GetMetadata())
			case "authenticator":
				cluster.Logging.Authenticator = types.Bool(true, logTypesAttr.GetMetadata())
			case "controllerManager":
				cluster.Logging.ControllerManager = types.Bool(true, logTypesAttr.GetMetadata())
			case "scheduler":
				cluster.Logging.Scheduler = types.Bool(true, logTypesAttr.GetMetadata())
			}
		}
	}

	if encryptBlock := resource.GetBlock("encryption_config"); encryptBlock.IsNotNil() {
		cluster.Encryption.Metadata = encryptBlock.GetMetadata()
		resourcesAttr := encryptBlock.GetAttribute("resources")
		if resourcesAttr.Contains("secrets") {
			cluster.Encryption.Secrets = types.Bool(true, resourcesAttr.GetMetadata())
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
		cidrsList := publicAccessCidrsAttr.ValueAsStrings()
		for _, cidr := range cidrsList {
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, types.String(cidr, publicAccessCidrsAttr.GetMetadata()))
		}
		if len(cidrsList) == 0 {
			cluster.PublicAccessCIDRs = append(cluster.PublicAccessCIDRs, types.StringDefault("0.0.0.0/0", vpcBlock.GetMetadata()))
		}
	}

	return cluster
}
