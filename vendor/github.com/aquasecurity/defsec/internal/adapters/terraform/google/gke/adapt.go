package gke

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/google/uuid"
	"github.com/zclconf/go-cty/cty"
)

func Adapt(modules terraform.Modules) gke.GKE {
	return gke.GKE{
		Clusters: (&adapter{
			modules:    modules,
			clusterMap: make(map[string]gke.Cluster),
		}).adaptClusters(),
	}
}

type adapter struct {
	modules    terraform.Modules
	clusterMap map[string]gke.Cluster
}

func (a *adapter) adaptClusters() []gke.Cluster {
	for _, module := range a.modules {
		for _, resource := range module.GetResourcesByType("google_container_cluster") {
			a.adaptCluster(resource, module)
		}
	}

	a.adaptNodePools()

	for id, cluster := range a.clusterMap {
		if len(cluster.NodePools) > 0 {
			cluster.NodeConfig = cluster.NodePools[0].NodeConfig
			a.clusterMap[id] = cluster
		}
	}

	var clusters []gke.Cluster
	for _, cluster := range a.clusterMap {
		clusters = append(clusters, cluster)
	}
	return clusters
}

func (a *adapter) adaptCluster(resource *terraform.Block, module *terraform.Module) {

	cluster := gke.Cluster{
		Metadata:  resource.GetMetadata(),
		NodePools: nil,
		IPAllocationPolicy: gke.IPAllocationPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
		},
		MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			CIDRs:    []types.StringValue{},
		},
		NetworkPolicy: gke.NetworkPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
		},
		PrivateCluster: gke.PrivateCluster{
			Metadata:           resource.GetMetadata(),
			EnablePrivateNodes: types.BoolDefault(false, resource.GetMetadata()),
		},
		LoggingService:    types.StringDefault("logging.googleapis.com/kubernetes", resource.GetMetadata()),
		MonitoringService: types.StringDefault("monitoring.googleapis.com/kubernetes", resource.GetMetadata()),
		PodSecurityPolicy: gke.PodSecurityPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
		},
		ClusterMetadata: gke.Metadata{
			Metadata:              resource.GetMetadata(),
			EnableLegacyEndpoints: types.BoolDefault(true, resource.GetMetadata()),
		},
		MasterAuth: gke.MasterAuth{
			Metadata: resource.GetMetadata(),
			ClientCertificate: gke.ClientCertificate{
				Metadata:         resource.GetMetadata(),
				IssueCertificate: types.BoolDefault(false, resource.GetMetadata()),
			},
			Username: types.StringDefault("", resource.GetMetadata()),
			Password: types.StringDefault("", resource.GetMetadata()),
		},
		NodeConfig: gke.NodeConfig{
			Metadata:  resource.GetMetadata(),
			ImageType: types.StringDefault("", resource.GetMetadata()),
			WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
				Metadata:     resource.GetMetadata(),
				NodeMetadata: types.StringDefault("", resource.GetMetadata()),
			},
			ServiceAccount: types.StringDefault("", resource.GetMetadata()),
		},
		EnableShieldedNodes:   types.BoolDefault(true, resource.GetMetadata()),
		EnableLegacyABAC:      types.BoolDefault(false, resource.GetMetadata()),
		ResourceLabels:        types.MapDefault(make(map[string]string), resource.GetMetadata()),
		RemoveDefaultNodePool: types.BoolDefault(false, resource.GetMetadata()),
	}

	if allocBlock := resource.GetBlock("ip_allocation_policy"); allocBlock.IsNotNil() {
		cluster.IPAllocationPolicy.Metadata = allocBlock.GetMetadata()
		cluster.IPAllocationPolicy.Enabled = types.Bool(true, allocBlock.GetMetadata())
	}

	if blocks := resource.GetBlocks("master_authorized_networks_config"); len(blocks) > 0 {
		cluster.MasterAuthorizedNetworks = adaptMasterAuthNetworksAsBlocks(resource, blocks)
	}

	if policyBlock := resource.GetBlock("network_policy"); policyBlock.IsNotNil() {
		enabledAttr := policyBlock.GetAttribute("enabled")
		cluster.NetworkPolicy.Metadata = policyBlock.GetMetadata()
		cluster.NetworkPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, policyBlock)
	}

	if privBlock := resource.GetBlock("private_cluster_config"); privBlock.IsNotNil() {
		privateNodesEnabledAttr := privBlock.GetAttribute("enable_private_nodes")
		cluster.PrivateCluster.Metadata = privBlock.GetMetadata()
		cluster.PrivateCluster.EnablePrivateNodes = privateNodesEnabledAttr.AsBoolValueOrDefault(false, privBlock)
	}

	loggingAttr := resource.GetAttribute("logging_service")
	cluster.LoggingService = loggingAttr.AsStringValueOrDefault("logging.googleapis.com/kubernetes", resource)
	monitoringServiceAttr := resource.GetAttribute("monitoring_service")
	cluster.MonitoringService = monitoringServiceAttr.AsStringValueOrDefault("monitoring.googleapis.com/kubernetes", resource)

	if policyBlock := resource.GetBlock("pod_security_policy_config"); policyBlock.IsNotNil() {
		enabledAttr := policyBlock.GetAttribute("enabled")
		cluster.PodSecurityPolicy.Metadata = policyBlock.GetMetadata()
		cluster.PodSecurityPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, policyBlock)
	}

	legacyMetadataAttr := resource.GetNestedAttribute("node_config.metadata.disable-legacy-endpoints")
	if legacyMetadataAttr.IsNotNil() {
		if legacyMetadataAttr.IsTrue() {
			cluster.ClusterMetadata.EnableLegacyEndpoints = types.Bool(false, legacyMetadataAttr.GetMetadata())
		} else if legacyMetadataAttr.IsFalse() {
			cluster.ClusterMetadata.EnableLegacyEndpoints = types.Bool(true, legacyMetadataAttr.GetMetadata())
		}
	}

	if masterBlock := resource.GetBlock("master_auth"); masterBlock.IsNotNil() {
		cluster.MasterAuth = adaptMasterAuth(masterBlock)
	}

	if configBlock := resource.GetBlock("node_config"); configBlock.IsNotNil() {
		cluster.NodeConfig = adaptNodeConfig(configBlock)
	}

	cluster.EnableShieldedNodes = resource.GetAttribute("enable_shielded_nodes").AsBoolValueOrDefault(true, resource)

	enableLegacyABACAttr := resource.GetAttribute("enable_legacy_abac")
	cluster.EnableLegacyABAC = enableLegacyABACAttr.AsBoolValueOrDefault(false, resource)

	resourceLabelsAttr := resource.GetAttribute("resource_labels")
	if resourceLabelsAttr.IsNotNil() {
		resourceLabels := make(map[string]string)
		_ = resourceLabelsAttr.Each(func(key, val cty.Value) {
			if key.Type() == cty.String && val.Type() == cty.String {
				resourceLabels[key.AsString()] = val.AsString()
			}
		})
		cluster.ResourceLabels = types.Map(resourceLabels, resourceLabelsAttr.GetMetadata())
	}

	cluster.RemoveDefaultNodePool = resource.GetAttribute("remove_default_node_pool").AsBoolValueOrDefault(false, resource)

	a.clusterMap[resource.ID()] = cluster
}

func (a *adapter) adaptNodePools() {
	for _, nodePoolBlock := range a.modules.GetResourcesByType("google_container_node_pool") {
		a.adaptNodePool(nodePoolBlock)
	}
}

func (a *adapter) adaptNodePool(resource *terraform.Block) {
	autoRepair := types.BoolDefault(false, resource.GetMetadata())
	autoUpgrade := types.BoolDefault(false, resource.GetMetadata())

	nodeConfig := gke.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: types.StringDefault("", resource.GetMetadata()),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: types.StringDefault("", resource.GetMetadata()),
		},
		ServiceAccount: types.StringDefault("", resource.GetMetadata()),
	}

	if resource.HasChild("management") {
		autoRepairAttr := resource.GetBlock("management").GetAttribute("auto_repair")
		autoRepair = autoRepairAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))

		autoUpgradeAttr := resource.GetBlock("management").GetAttribute("auto_upgrade")
		autoUpgrade = autoUpgradeAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))
	}

	if resource.HasChild("node_config") {
		nodeConfig = adaptNodeConfig(resource.GetBlock("node_config"))
	}

	nodePool := gke.NodePool{
		Metadata: resource.GetMetadata(),
		Management: gke.Management{
			Metadata:          resource.GetMetadata(),
			EnableAutoRepair:  autoRepair,
			EnableAutoUpgrade: autoUpgrade,
		},
		NodeConfig: nodeConfig,
	}

	clusterAttr := resource.GetAttribute("cluster")
	if referencedCluster, err := a.modules.GetReferencedBlock(clusterAttr, resource); err == nil {
		if referencedCluster.TypeLabel() == "google_container_cluster" {
			if cluster, ok := a.clusterMap[referencedCluster.ID()]; ok {
				cluster.NodePools = append(cluster.NodePools, nodePool)
				a.clusterMap[referencedCluster.ID()] = cluster
				return
			}
		}
	}

	// we didn't find a cluster to put the nodepool in, so create a placeholder
	a.clusterMap[uuid.NewString()] = gke.Cluster{
		Metadata:  types.NewUnmanagedMetadata(),
		NodePools: []gke.NodePool{nodePool},
	}
}

func adaptNodeConfig(resource *terraform.Block) gke.NodeConfig {
	imageTypeAttr := resource.GetAttribute("image_type")
	imageType := imageTypeAttr.AsStringValueOrDefault("", resource)

	modeAttr := resource.GetNestedAttribute("workload_metadata_config.node_metadata")
	if modeAttr.IsNil() {
		modeAttr = resource.GetNestedAttribute("workload_metadata_config.mode") // try newest version
	}
	nodeMetadata := modeAttr.AsStringValueOrDefault("UNSPECIFIED", resource)

	serviceAcc := resource.GetAttribute("service_account").AsStringValueOrDefault("", resource)

	return gke.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: imageType,
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: nodeMetadata,
		},
		ServiceAccount: serviceAcc,
	}
}

func adaptMasterAuth(resource *terraform.Block) gke.MasterAuth {
	issueClientCert := types.BoolDefault(false, resource.GetMetadata())

	if resource.HasChild("client_certificate_config") {
		clientCertAttr := resource.GetBlock("client_certificate_config").GetAttribute("issue_client_certificate")
		issueClientCert = clientCertAttr.AsBoolValueOrDefault(false, resource.GetBlock("client_certificate_config"))
	}

	username := resource.GetAttribute("username").AsStringValueOrDefault("", resource)
	password := resource.GetAttribute("password").AsStringValueOrDefault("", resource)

	return gke.MasterAuth{
		Metadata: resource.GetMetadata(),
		ClientCertificate: gke.ClientCertificate{
			Metadata:         resource.GetMetadata(),
			IssueCertificate: issueClientCert,
		},
		Username: username,
		Password: password,
	}
}

func adaptMasterAuthNetworksAsBlocks(parent *terraform.Block, blocks terraform.Blocks) gke.MasterAuthorizedNetworks {
	var cidrs []types.StringValue
	for _, block := range blocks {
		for _, cidrBlock := range block.GetBlocks("cidr_blocks") {
			if cidrAttr := cidrBlock.GetAttribute("cidr_block"); cidrAttr.IsNotNil() {
				for _, cidr := range cidrAttr.ValueAsStrings() {
					cidrs = append(cidrs, types.String(cidr, cidrAttr.GetMetadata()))
				}
			}
		}
	}
	enabled := types.Bool(true, blocks[0].GetMetadata())
	return gke.MasterAuthorizedNetworks{
		Metadata: parent.GetMetadata(),
		Enabled:  enabled,
		CIDRs:    cidrs,
	}
}
