# Trivy Operator  

Trivy has a native [Kubernetes Operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) which continuously scans your Kubernetes cluster for security issues, and generates security reports as Kubernetes [Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/). It does it by watching Kubernetes for state changes and automatically triggering scans in response to changes, for example initiating a vulnerability scan when a new Pod is created.


> Kubernetes-native security toolkit. ([Documentation](https://aquasecurity.github.io/trivy-operator/latest)).

<figure>
  <figcaption>Workload reconcilers discover K8s controllers, manage scan jobs, and create VulnerabilityReport and ConfigAuditReport objects.</figcaption>
</figure>
