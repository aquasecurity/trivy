# Kubernetes

When scanning a Kubernetes cluster, Trivy differentiates between the following:

1. Cluster infrastructure (e.g api-server, kubelet, addons)
1. Cluster configuration (e.g Roles, ClusterRoles). 
1. Application workloads (e.g nginx, postgresql).

When scanning any of the above, Trivy differentiates between the Kubernetes Resource definition (i.e the YAML that defines it), and the container image if relevant.

Container image is scanned for:
- Vulnerabilities
- Misconfigurations
- Exposed secrets

Kubernetes resource definition is scanned for:
- Vulnerabilities - partially supported through [KBOM scanning](#KBOM)
- Misconfigurations
- Exposed secrets

To learn more, please see the [documentation for Kubernetes scanning](../target/kubernetes.md)
