package gke

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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
			Enabled:  defsecTypes.BoolDefault(false, resource.GetMetadata()),
		},
		MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
			Metadata: resource.GetMetadata(),
			Enabled:  defsecTypes.BoolDefault(false, resource.GetMetadata()),
			CIDRs:    []defsecTypes.StringValue{},
		},
		NetworkPolicy: gke.NetworkPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  defsecTypes.BoolDefault(false, resource.GetMetadata()),
		},
		PrivateCluster: gke.PrivateCluster{
			Metadata:           resource.GetMetadata(),
			EnablePrivateNodes: defsecTypes.BoolDefault(false, resource.GetMetadata()),
		},
		LoggingService:    defsecTypes.StringDefault("logging.googleapis.com/kubernetes", resource.GetMetadata()),
		MonitoringService: defsecTypes.StringDefault("monitoring.googleapis.com/kubernetes", resource.GetMetadata()),
		MasterAuth: gke.MasterAuth{
			Metadata: resource.GetMetadata(),
			ClientCertificate: gke.ClientCertificate{
				Metadata:         resource.GetMetadata(),
				IssueCertificate: defsecTypes.BoolDefault(false, resource.GetMetadata()),
			},
			Username: defsecTypes.StringDefault("", resource.GetMetadata()),
			Password: defsecTypes.StringDefault("", resource.GetMetadata()),
		},
		NodeConfig: gke.NodeConfig{
			Metadata:  resource.GetMetadata(),
			ImageType: defsecTypes.StringDefault("", resource.GetMetadata()),
			WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
				Metadata:     resource.GetMetadata(),
				NodeMetadata: defsecTypes.StringDefault("", resource.GetMetadata()),
			},
			ServiceAccount:        defsecTypes.StringDefault("", resource.GetMetadata()),
			EnableLegacyEndpoints: defsecTypes.BoolDefault(true, resource.GetMetadata()),
		},
		EnableShieldedNodes:   defsecTypes.BoolDefault(true, resource.GetMetadata()),
		EnableLegacyABAC:      defsecTypes.BoolDefault(false, resource.GetMetadata()),
		ResourceLabels:        defsecTypes.MapDefault(make(map[string]string), resource.GetMetadata()),
		RemoveDefaultNodePool: defsecTypes.BoolDefault(false, resource.GetMetadata()),
		EnableAutpilot:        defsecTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if allocBlock := resource.GetBlock("ip_allocation_policy"); allocBlock.IsNotNil() {
		cluster.IPAllocationPolicy.Metadata = allocBlock.GetMetadata()
		cluster.IPAllocationPolicy.Enabled = defsecTypes.Bool(true, allocBlock.GetMetadata())
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

	if masterBlock := resource.GetBlock("master_auth"); masterBlock.IsNotNil() {
		cluster.MasterAuth = adaptMasterAuth(masterBlock)
	}

	if configBlock := resource.GetBlock("node_config"); configBlock.IsNotNil() {
		if configBlock.GetBlock("metadata").IsNotNil() {
			cluster.NodeConfig.Metadata = configBlock.GetBlock("metadata").GetMetadata()
		}
		cluster.NodeConfig = adaptNodeConfig(configBlock)
	}

	cluster.EnableShieldedNodes = resource.GetAttribute("enable_shielded_nodes").AsBoolValueOrDefault(true, resource)

	enableLegacyABACAttr := resource.GetAttribute("enable_legacy_abac")
	cluster.EnableLegacyABAC = enableLegacyABACAttr.AsBoolValueOrDefault(false, resource)

	cluster.EnableAutpilot = resource.GetAttribute("enable_autopilot").AsBoolValueOrDefault(false, resource)

	resourceLabelsAttr := resource.GetAttribute("resource_labels")
	if resourceLabelsAttr.IsNotNil() {
		cluster.ResourceLabels = resourceLabelsAttr.AsMapValue()
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
	nodeConfig := gke.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: defsecTypes.StringDefault("", resource.GetMetadata()),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: defsecTypes.StringDefault("", resource.GetMetadata()),
		},
		ServiceAccount:        defsecTypes.StringDefault("", resource.GetMetadata()),
		EnableLegacyEndpoints: defsecTypes.BoolDefault(true, resource.GetMetadata()),
	}

	management := gke.Management{
		Metadata:          resource.GetMetadata(),
		EnableAutoRepair:  defsecTypes.BoolDefault(false, resource.GetMetadata()),
		EnableAutoUpgrade: defsecTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if resource.HasChild("management") {
		management.Metadata = resource.GetBlock("management").GetMetadata()

		autoRepairAttr := resource.GetBlock("management").GetAttribute("auto_repair")
		management.EnableAutoRepair = autoRepairAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))

		autoUpgradeAttr := resource.GetBlock("management").GetAttribute("auto_upgrade")
		management.EnableAutoUpgrade = autoUpgradeAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))
	}

	if resource.HasChild("node_config") {
		nodeConfig = adaptNodeConfig(resource.GetBlock("node_config"))
	}

	nodePool := gke.NodePool{
		Metadata:   resource.GetMetadata(),
		Management: management,
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
		Metadata:  defsecTypes.NewUnmanagedMetadata(),
		NodePools: []gke.NodePool{nodePool},
		IPAllocationPolicy: gke.IPAllocationPolicy{
			Metadata: defsecTypes.NewUnmanagedMetadata(),
			Enabled:  defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		},
		MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
			Metadata: defsecTypes.NewUnmanagedMetadata(),
			Enabled:  defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			CIDRs:    nil,
		},
		NetworkPolicy: gke.NetworkPolicy{
			Metadata: defsecTypes.NewUnmanagedMetadata(),
			Enabled:  defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		},
		PrivateCluster: gke.PrivateCluster{
			Metadata:           defsecTypes.NewUnmanagedMetadata(),
			EnablePrivateNodes: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		},
		LoggingService:    defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
		MonitoringService: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
		MasterAuth: gke.MasterAuth{
			Metadata: defsecTypes.NewUnmanagedMetadata(),
			ClientCertificate: gke.ClientCertificate{
				Metadata:         defsecTypes.NewUnmanagedMetadata(),
				IssueCertificate: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			},
			Username: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			Password: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
		},
		NodeConfig: gke.NodeConfig{
			Metadata:  defsecTypes.NewUnmanagedMetadata(),
			ImageType: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
				Metadata:     defsecTypes.NewUnmanagedMetadata(),
				NodeMetadata: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			},
			ServiceAccount:        defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			EnableLegacyEndpoints: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		},
		EnableShieldedNodes:   defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		EnableLegacyABAC:      defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		ResourceLabels:        defsecTypes.MapDefault(nil, defsecTypes.NewUnmanagedMetadata()),
		RemoveDefaultNodePool: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		EnableAutpilot:        defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
	}
}

func adaptNodeConfig(resource *terraform.Block) gke.NodeConfig {

	config := gke.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: resource.GetAttribute("image_type").AsStringValueOrDefault("", resource),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: defsecTypes.StringDefault("UNSPECIFIED", resource.GetMetadata()),
		},
		ServiceAccount:        resource.GetAttribute("service_account").AsStringValueOrDefault("", resource),
		EnableLegacyEndpoints: defsecTypes.BoolDefault(true, resource.GetMetadata()),
	}

	if metadata := resource.GetAttribute("metadata"); metadata.IsNotNil() {
		legacyMetadata := metadata.MapValue("disable-legacy-endpoints")
		if legacyMetadata.IsWhollyKnown() && legacyMetadata.Type() == cty.Bool {
			config.EnableLegacyEndpoints = defsecTypes.Bool(legacyMetadata.False(), metadata.GetMetadata())
		}
	}

	workloadBlock := resource.GetBlock("workload_metadata_config")
	if workloadBlock.IsNotNil() {
		config.WorkloadMetadataConfig.Metadata = workloadBlock.GetMetadata()
		modeAttr := workloadBlock.GetAttribute("node_metadata")
		if modeAttr.IsNil() {
			modeAttr = workloadBlock.GetAttribute("mode") // try newest version
		}
		config.WorkloadMetadataConfig.NodeMetadata = modeAttr.AsStringValueOrDefault("UNSPECIFIED", workloadBlock)
	}

	return config
}

func adaptMasterAuth(resource *terraform.Block) gke.MasterAuth {
	clientCert := gke.ClientCertificate{
		Metadata:         resource.GetMetadata(),
		IssueCertificate: defsecTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if resource.HasChild("client_certificate_config") {
		clientCertAttr := resource.GetBlock("client_certificate_config").GetAttribute("issue_client_certificate")
		clientCert.IssueCertificate = clientCertAttr.AsBoolValueOrDefault(false, resource.GetBlock("client_certificate_config"))
		clientCert.Metadata = resource.GetBlock("client_certificate_config").GetMetadata()
	}

	username := resource.GetAttribute("username").AsStringValueOrDefault("", resource)
	password := resource.GetAttribute("password").AsStringValueOrDefault("", resource)

	return gke.MasterAuth{
		Metadata:          resource.GetMetadata(),
		ClientCertificate: clientCert,
		Username:          username,
		Password:          password,
	}
}

func adaptMasterAuthNetworksAsBlocks(parent *terraform.Block, blocks terraform.Blocks) gke.MasterAuthorizedNetworks {
	var cidrs []defsecTypes.StringValue
	for _, block := range blocks {
		for _, cidrBlock := range block.GetBlocks("cidr_blocks") {
			if cidrAttr := cidrBlock.GetAttribute("cidr_block"); cidrAttr.IsNotNil() {
				cidrs = append(cidrs, cidrAttr.AsStringValues()...)
			}
		}
	}
	enabled := defsecTypes.Bool(true, blocks[0].GetMetadata())
	return gke.MasterAuthorizedNetworks{
		Metadata: blocks[0].GetMetadata(),
		Enabled:  enabled,
		CIDRs:    cidrs,
	}
}
