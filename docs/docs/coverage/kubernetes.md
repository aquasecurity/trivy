# Kubernetes

When scanning a Kubernetes cluster, Trivy differentiates between the following:

1. Cluster infrastructure (e.g api-server, kubelet, addons)
1. Cluster configuration (e.g Roles, ClusterRoles). 
1. Application workloads (e.g nginx, postgresql).

Whenever Trivy scans either of these Kubernetes resources, the container image is scanned separately to the Kubernetes resource definition (the YAML manifest) that defines the resource.
When scanning any of the above, the container image is scanned separately to the Kubernetes resource definition (the YAML manifest) that defines the resource.

Container image is scanned for:

- Vulnerabilities
- Misconfigurations
- Exposed secrets

Kubernetes resource definition is scanned for:

- Vulnerabilities - partially supported through [KBOM scanning](../target/kubernetes.md#kbom)
- Misconfigurations
- Exposed secrets

To learn more, please see the [documentation for Kubernetes scanning](../target/kubernetes.md).
