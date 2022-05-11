package compute

var terraformKubernetesClusterAutoUpgradeBadExample = []string{
	`
resource "digitalocean_kubernetes_cluster" "foo" {
	name    	 = "foo"
	region  	 = "nyc1"
	version 	 = "1.20.2-do.0"
	auto_upgrade = false

	node_pool {
		name       = "autoscale-worker-pool"
		size       = "s-2vcpu-2gb"
		auto_scale = true
		min_nodes  = 1
		max_nodes  = 5
	}
}
`,
}

var terraformKubernetesClusterAutoUpgradeGoodExample = []string{
	`
resource "digitalocean_kubernetes_cluster" "foo" {
	name    	 = "foo"
	region  	 = "nyc1"
	version 	 = "1.20.2-do.0"
	auto_upgrade = true

	node_pool {
		name       = "autoscale-worker-pool"
		size       = "s-2vcpu-2gb"
		auto_scale = true
		min_nodes  = 1
		max_nodes  = 5
	}
}
`,
}

var terraformKubernetesClusterAutoUpgradeLinks = []string{
	`https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#auto-upgrade-example`,
}

var terraformKubernetesAutoUpgradeMarkdown = ``
