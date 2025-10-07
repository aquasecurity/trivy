package gke

import (
	"github.com/google/uuid"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
			a.adaptCluster(resource)
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

func (a *adapter) adaptCluster(resource *terraform.Block) {

	cluster := gke.Cluster{
		Metadata:  resource.GetMetadata(),
		NodePools: nil,
		IPAllocationPolicy: gke.IPAllocationPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			CIDRs:    []iacTypes.StringValue{},
		},
		NetworkPolicy: gke.NetworkPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		DatapathProvider: resource.GetAttribute("datapath_provider").
			AsStringValueOrDefault("DATAPATH_PROVIDER_UNSPECIFIED", resource),
		PrivateCluster: gke.PrivateCluster{
			Metadata:           resource.GetMetadata(),
			EnablePrivateNodes: iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		LoggingService:    iacTypes.StringDefault("logging.googleapis.com/kubernetes", resource.GetMetadata()),
		MonitoringService: iacTypes.StringDefault("monitoring.googleapis.com/kubernetes", resource.GetMetadata()),
		MasterAuth: gke.MasterAuth{
			Metadata: resource.GetMetadata(),
			ClientCertificate: gke.ClientCertificate{
				Metadata:         resource.GetMetadata(),
				IssueCertificate: iacTypes.BoolDefault(false, resource.GetMetadata()),
			},
			Username: iacTypes.StringDefault("", resource.GetMetadata()),
			Password: iacTypes.StringDefault("", resource.GetMetadata()),
		},
		NodeConfig: gke.NodeConfig{
			Metadata:  resource.GetMetadata(),
			ImageType: iacTypes.StringDefault("", resource.GetMetadata()),
			WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
				Metadata:     resource.GetMetadata(),
				NodeMetadata: iacTypes.StringDefault("", resource.GetMetadata()),
			},
			ServiceAccount:        iacTypes.StringDefault("", resource.GetMetadata()),
			EnableLegacyEndpoints: iacTypes.BoolDefault(true, resource.GetMetadata()),
		},
		EnableShieldedNodes:   iacTypes.BoolDefault(true, resource.GetMetadata()),
		EnableLegacyABAC:      iacTypes.BoolDefault(false, resource.GetMetadata()),
		ResourceLabels:        iacTypes.MapDefault(make(map[string]string), resource.GetMetadata()),
		RemoveDefaultNodePool: iacTypes.BoolDefault(false, resource.GetMetadata()),
		EnableAutpilot:        iacTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if allocBlock := resource.GetBlock("ip_allocation_policy"); allocBlock.IsNotNil() {
		cluster.IPAllocationPolicy.Metadata = allocBlock.GetMetadata()
		cluster.IPAllocationPolicy.Enabled = iacTypes.Bool(true, allocBlock.GetMetadata())
	}

	if blocks := resource.GetBlocks("master_authorized_networks_config"); len(blocks) > 0 {
		cluster.MasterAuthorizedNetworks = adaptMasterAuthNetworksAsBlocks(blocks)
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
		cluster.NodeConfig = adaptNodeConfig(configBlock)
	}

	if autoScalingBlock := resource.GetBlock("cluster_autoscaling"); autoScalingBlock.IsNotNil() {
		cluster.AutoScaling = gke.AutoScaling{
			Metadata: autoScalingBlock.GetMetadata(),
			Enabled:  autoScalingBlock.GetAttribute("enabled").AsBoolValueOrDefault(false, autoScalingBlock),
		}

		if b := autoScalingBlock.GetBlock("auto_provisioning_defaults"); b.IsNotNil() {
			cluster.AutoScaling.AutoProvisioningDefaults = gke.AutoProvisioningDefaults{
				Metadata:       b.GetMetadata(),
				ServiceAccount: b.GetAttribute("service_account").AsStringValueOrDefault("", b),
				Management:     adaptManagement(b),
				ImageType:      b.GetAttribute("image_type").AsStringValueOrDefault("", b),
			}
		}
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

func adaptManagement(parent *terraform.Block) gke.Management {
	b := parent.GetBlock("management")
	if b.IsNil() {
		return gke.Management{
			Metadata:          parent.GetMetadata(),
			EnableAutoRepair:  iacTypes.BoolDefault(false, parent.GetMetadata()),
			EnableAutoUpgrade: iacTypes.BoolDefault(false, parent.GetMetadata()),
		}
	}

	return gke.Management{
		Metadata:          b.GetMetadata(),
		EnableAutoRepair:  b.GetAttribute("auto_repair").AsBoolValueOrDefault(false, b),
		EnableAutoUpgrade: b.GetAttribute("auto_upgrade").AsBoolValueOrDefault(false, b),
	}
}

func (a *adapter) adaptNodePools() {
	for _, nodePoolBlock := range a.modules.GetResourcesByType("google_container_node_pool") {
		a.adaptNodePool(nodePoolBlock)
	}
}

func (a *adapter) adaptNodePool(resource *terraform.Block) {
	nodeConfig := gke.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: iacTypes.StringDefault("", resource.GetMetadata()),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: iacTypes.StringDefault("", resource.GetMetadata()),
		},
		ServiceAccount:        iacTypes.StringDefault("", resource.GetMetadata()),
		EnableLegacyEndpoints: iacTypes.BoolDefault(true, resource.GetMetadata()),
	}

	if nodeConfigBlock := resource.GetBlock("node_config"); nodeConfigBlock.IsNotNil() {
		nodeConfig = adaptNodeConfig(nodeConfigBlock)
	}

	nodePool := gke.NodePool{
		Metadata:   resource.GetMetadata(),
		Management: adaptManagement(resource),
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
		Metadata:  iacTypes.NewUnmanagedMetadata(),
		NodePools: []gke.NodePool{nodePool},
		IPAllocationPolicy: gke.IPAllocationPolicy{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Enabled:  iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		},
		MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Enabled:  iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
			CIDRs:    nil,
		},
		NetworkPolicy: gke.NetworkPolicy{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Enabled:  iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		},
		PrivateCluster: gke.PrivateCluster{
			Metadata:           iacTypes.NewUnmanagedMetadata(),
			EnablePrivateNodes: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		},
		LoggingService:    iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		MonitoringService: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		MasterAuth: gke.MasterAuth{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			ClientCertificate: gke.ClientCertificate{
				Metadata:         iacTypes.NewUnmanagedMetadata(),
				IssueCertificate: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
			},
			Username: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			Password: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		},
		NodeConfig: gke.NodeConfig{
			Metadata:  iacTypes.NewUnmanagedMetadata(),
			ImageType: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
				Metadata:     iacTypes.NewUnmanagedMetadata(),
				NodeMetadata: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			},
			ServiceAccount:        iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			EnableLegacyEndpoints: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		},
		EnableShieldedNodes:   iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		EnableLegacyABAC:      iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		ResourceLabels:        iacTypes.MapDefault(nil, iacTypes.NewUnmanagedMetadata()),
		RemoveDefaultNodePool: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		EnableAutpilot:        iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
	}
}

func adaptNodeConfig(resource *terraform.Block) gke.NodeConfig {

	config := gke.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: resource.GetAttribute("image_type").AsStringValueOrDefault("", resource),
		WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: iacTypes.StringDefault("UNSPECIFIED", resource.GetMetadata()),
		},
		ServiceAccount:        resource.GetAttribute("service_account").AsStringValueOrDefault("", resource),
		EnableLegacyEndpoints: iacTypes.BoolDefault(true, resource.GetMetadata()),
	}

	if metadata := resource.GetAttribute("metadata"); metadata.IsNotNil() {
		disableLegacy := metadata.MapValue("disable-legacy-endpoints")
		if disableLegacy.IsKnown() {
			var enableLegacyEndpoints bool
			switch disableLegacy.Type() {
			case cty.Bool:
				enableLegacyEndpoints = disableLegacy.False()
			case cty.String:
				enableLegacyEndpoints = disableLegacy.AsString() == "false"
			}

			config.EnableLegacyEndpoints = iacTypes.Bool(enableLegacyEndpoints, metadata.GetMetadata())
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
		IssueCertificate: iacTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if certConfigBlock := resource.GetBlock("client_certificate_config"); certConfigBlock.IsNotNil() {
		clientCertAttr := certConfigBlock.GetAttribute("issue_client_certificate")
		clientCert.IssueCertificate = clientCertAttr.AsBoolValueOrDefault(false, certConfigBlock)
		clientCert.Metadata = certConfigBlock.GetMetadata()
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

func adaptMasterAuthNetworksAsBlocks(blocks terraform.Blocks) gke.MasterAuthorizedNetworks {
	var cidrs []iacTypes.StringValue
	for _, block := range blocks {
		for _, cidrBlock := range block.GetBlocks("cidr_blocks") {
			if cidrAttr := cidrBlock.GetAttribute("cidr_block"); cidrAttr.IsNotNil() {
				cidrs = append(cidrs, cidrAttr.AsStringValues()...)
			}
		}
	}
	enabled := iacTypes.Bool(true, blocks[0].GetMetadata())
	return gke.MasterAuthorizedNetworks{
		Metadata: blocks[0].GetMetadata(),
		Enabled:  enabled,
		CIDRs:    cidrs,
	}
}
