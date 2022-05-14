# Trivy-Operator 

## Overview

This operator automatically updates security report resources in response to workload and other changes on a Kubernetes
cluster - for example, initiating a vulnerability scan and configuration audit when a new Pod is started.

<figure>
  <img src="./images/operator/trivy-operator-workloads.png" />
  <figcaption>Workload reconcilers discover K8s controllers, manage scan jobs, and create VulnerabilityReport and ConfigAuditReport objects.</figcaption>
</figure>



Rescan is also triggered whenever a config of a configuration audit plugin has changed. For example, when a new OPA
policy script is added to the Confest plugin config. This is implemented by adding the label named `plugin-config-hash`
to ConfigAuditReport instances. The plugins' config reconciler watches the ConfigMap that holds plugin settings
and computes a hash from the ConfigMap's data. The hash is then compared with values of the `plugin-config-hash` labels.
If hashes are not equal then affected ConfigAuditReport objects are deleted, which in turn triggers rescan - this time
with new plugin's configuration.

<figure>
  <img src="./images/operator/trivy-operator-config.png" />
  <figurecaption>Plugin configuration reconciler deletes ConfigAuditReports whenever the configuration changes.</figurecaption>
</figure>

## What's Next?

- Install the operator and follow the [Getting Started](./getting-started.md) guide.

[vulnerabilityreports]: ./../crds/vulnerability-report.md
[configauditreports]: ./../crds/configaudit-report.md
[ciskubebenchreports]: ./../crds/ciskubebench-report.md
[kubehunterreports]: ./../crds/kubehunter-report.md
[clustercompliancereports]: ./../crds/clustercompliance-report.md
[clustercompliancedetailreports]: ./../crds/clustercompliancedetail-report.md

[k8s-garbage-collection]: https://kubernetes.io/docs/concepts/workloads/controllers/garbage-collection/
