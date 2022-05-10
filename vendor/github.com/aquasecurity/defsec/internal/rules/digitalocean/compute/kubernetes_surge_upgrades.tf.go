package compute

var terraformKubernetesClusterSurgeUpgradesBadExamples = []string{
	`
resource "digitalocean_kubernetes_cluster" "surge_upgrade_bad" {
	name   = "foo"
	region = "nyc1"
	version = "1.20.2-do.0"
	surge_upgrade = false
	
	node_pool {
		name       = "worker-pool"
		size       = "s-2vcpu-2gb"
		node_count = 3
	
		taint {
			key    = "workloadKind"
			value  = "database"
			effect = "NoSchedule"
		}
	}
}
 `,
}

var terraformKubernetesClusterSurgeUpgradesGoodExamples = []string{
	`
resource "digitalocean_kubernetes_cluster" "surge_upgrade_good" {
	name   = "foo"
	region = "nyc1"
	version = "1.20.2-do.0"
	surge_upgrade = true

	node_pool {
		name       = "worker-pool"
		size       = "s-2vcpu-2gb"
		node_count = 3
	
		taint {
			key    = "workloadKind"
			value  = "database"
			effect = "NoSchedule"
		}
	}
}
 `,
}

var terraformKubernetesClusterSurgeUpgradeLinks = []string{
	`https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#surge_upgrade`,
}

var terraformKubernetesClusterSurgeUpgradesMarkdown = ``
