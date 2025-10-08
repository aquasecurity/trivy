package container

import (
	"github.com/aquasecurity/trivy/internal/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/container"
)

func Adapt(deployment azure.Deployment) container.Container {
	return container.Container{
		KubernetesClusters: adaptKubernetesClusters(deployment),
	}
}

func adaptKubernetesClusters(_ azure.Deployment) []container.KubernetesCluster {

	return nil
}
