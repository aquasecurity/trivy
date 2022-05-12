# Configuration Auditing

As your organization deploys containerized workloads in Kubernetes environments, you will be faced with many
configuration choices related to images, containers, control plane, and data plane. Setting these configurations
improperly creates a high-impact security and compliance risk. DevOps, and platform owners need the ability to
continuously assess build artifacts, workloads, and infrastructure against configuration hardening standards to
remediate any violations.

trivy-operator configuration audit capabilities are purpose-built for Kubernetes environments. In particular, trivy
Operator continuously checks images, workloads, and Kubernetes infrastructure components against common configurations
security standards and generates detailed assessment reports, which are then stored in the default Kubernetes database.

Kubernetes applications and other core configuration objects, such as Ingress, NetworkPolicy, ResourceQuota, RBAC
resources, are evaluated against [Built-in Policies]. Beyond that, cluster nodes are constantly assessed against the CIS
Kubernetes Benchmarks with the kube-bench [Infrastructure Scanner]. The results of all these scans are stored as
[ConfigAuditReport], [ClusterConfigAuditReport], and [CISKubeBenchReport] resources, which could be further aggregated
into a [ClusterComplianceReport] such as [NSA, CISA Kubernetes Hardening Guidance].

Additionally, application and infrastructure owners can integrate these reports into incident response workflows for
active remediation.

[Built-in Policies]: ./built-in-policies.md
[Infrastructure Scanner]: ./infrastructure-scanners/index.md
[ConfigAuditReport]: ./../crds/configaudit-report.md
[ClusterConfigAuditReport]: ./../crds/clusterconfigaudit-report.md
[CISKubeBenchReport]: ./../crds/ciskubebench-report.md
[ClusterComplianceReport]: ./../crds/clustercompliance-report.md
[NSA, CISA Kubernetes Hardening Guidance]: ./../compliance/nsa-1.0.md
