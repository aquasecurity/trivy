# KubeHunterReport

The KubeHunterReport is a cluster scoped resource which represents the outcome of running pen tests against your cluster.
Currently the data model is the same as [kube-hunter]'s output, but we can make it more generic to onboard third
party pen testing tools.

As shown in the following listing there's zero to one instances of KubeHunterReports with hardcoded name `cluster`.
Since there's no built-in Kubernetes resource that represents a cluster trivy-operator does not set any owner reference.

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: KubeHunterReport
metadata:
  name: cluster
  labels:
    trivy-operator.resource.kind: Cluster
    trivy-operator.resource.name: cluster
  uid: 958ca06b-6393-4e44-a6a6-11ce823c94fe
report:
  scanner:
    name: kube-hunter
    vendor: Aqua Security
    version: 0.4.1
  summary:
    highCount: 0
    lowCount: 1
    mediumCount: 0
    unknownCount: 0
  vulnerabilities:
  - avd_reference: https://avd.aquasec.com/kube-hunter/none/
    category: Access Risk
    description: |-
      CAP_NET_RAW is enabled by default for pods.
          If an attacker manages to compromise a pod,
          they could potentially take advantage of this capability to perform network
          attacks on other pods running on the same node
    evidence: ""
    location: Local to Pod (cf63974f-26a4-43f7-9409-44102fc75900-sl7vq)
    severity: low
    vid: None
    vulnerability: CAP_NET_RAW Enabled
```

[kube-hunter]: https://github.com/aquasecurity/kube-hunter
