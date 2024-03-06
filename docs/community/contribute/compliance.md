# Contribute Compliance Checks in Trivy

Trivy supports several different compliance checks. The details on compliance Scanning with Trivy are provided in the [compliance documentation](../../docs/compliance/compliance.md).
All of the Compliance Checks currently available in Trivy can be found in the `trivy-policies/specs/compliance/` directory ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/specs/compliance)).

New checks are based on the custom compliance report detailed in the [main documentation.](../../docs/compliance/compliance/#custom-compliance)

The Trivy community and maintainers are still working on expanding the selection of Compliance Checks in Trivy
This section details how community members can contribute new Compliance Specs.

## Importing Compliance Frameworks from kube-bench

Compliance Specs can be based on the following:

- Import existing compliance specs from Kube-Bench into Trivy. The Kube-Bench compliance specs can be found under `kube-bench/cfg` ([Link](https://github.com/aquasecurity/kube-bench/tree/main/cfg)).
- Based on new compliance reports becoming available or identifying missing compliance specs that Trivy users would like to access; those might be based CIS Benchmarks and similar compliance reports.

### Create a new Compliance Spec

The existing compliance checks in Trivy are located under the `trivy-policies/specs/compliance/` directory ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/specs/compliance)).

Create a new file under `trivy-policies/specs/compliance/` and name the file in the format of "provider-resource-spectype-version". For ecample AWS CIS Benchmarks for EKS version 1.4: `aws-eks-cis-1.4.yaml`.

### Minimum spec structure

The structure of the compliance check is detailed in the [main documentation](../../docs/compliance/compliance/#custom-compliance). For example, the beginning of the AWS CIS Benchmarks for EKS version 1.4 spec looks like this:

```
spec:
  id: eks-cis
  title: AWS EKS CIS Foundations v1.4
  description: AWS EKS CIS Foundations
  version: "1.4"
  relatedResources:
  - https://www.cisecurity.org/benchmark/amazon_web_services
  controls:
  - id: 2.1.1
    name: Enable audit Logs (Automated)
    description: |
      Control plane logs provide visibility into operation of the EKS Control plane components ystems. 
      The API server audit logs record all accepted and rejected requests in the cluster. 
      When enabled via EKS configuration the control plane logs for a cluster are exported to a CloudWatch 
      Log Group for persistence.
    checks: null
    severity: MEDIUM
  - id: 3.1.1
    name: Ensure that the kubeconfig file permissions are set to 644 or more restrictive (Manual)
    description: |
      If kubelet is running, and if it is configured by a kubeconfig file, ensure that the proxy kubeconfig 
      file has permissions of 644 or more restrictive
      Check with the following command: 
      > sudo systemctl status kubelet
    checks: null
    severity: HIGH
  - id: 3.1.2
    name: Ensure that the kubelet service file ownership is set to root:root (Manual)
    description: Ensure that the kubelet service file ownership is set to root:root
    checks:
      - id: AVD-KCV-0070
    severity: HIGH
    ....
```

The first section in the spec is focused on the metadata of the spec. Replace all the fields of the metadata with the information relevant to the compliance Spec that will be added.

- `id` -- This ID is composed of the resource that this check focuses on and the type of compliance check
- `title` -- A short title of the spec
- `description` -- This can be a longer description of the compliance spec
- `version` -- The compliance spec version that the compliance check targets. For instance, for CIS Benchmarks version 1.4, the version will be `1.4`.
- `relatedResources` -- Any resources that relate to this compliance check and can provide users with more information in the future.

The second section details all of the checks that make up the compliance check. These checks are detailed under `controls`.

  - `id` -- has to be the ID from the official compliance documentation such as the CIS Benchmark version.
  - `name` --  is the name of the check in short format.
  - `description` -- is a description of how the resource should be configured.
  - `checks.id` -- is the AVD ID or AVD IDs referenced that perform the Rego check for this compliance check, more information is provided below.
  - `severity` -- more information provided below.

#### Populating the `control` section

Compliance checks detail a set of checks that should pass so that the resource is compliant with the benchmark specifications. There are two ways in which Trivy compliance checks can enforce the compliance specification.

**1. Referencing the check that is already part of Trivy.**

Trivy has a comprehensive list of checks as part of its misconfiguration scanning. These can be found in the `trivy-policies/checks` directory ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/checks)). If the check is present, the AVD_ID and other information from the check has to be used.

If you are adding new compliance checks to Kubernetes e.g. AWS EKS CIS Benchmarks, chances are high that the compliance Check you would like to add has already been defined in the general k8s-ci-v.000.yaml. 

For example, the following check is detailed in the AWS EKS CIS v1.4 Benchmark:
`3.1.2 Ensure that the kubelet kubeconfig file ownership is set to root:root (Manual)`

This check can be found in the general K8s CIS Compliance Benchmark: `k8s-cis-1.23.yaml` ([Link](https://github.com/aquasecurity/trivy-policies/blob/31e779916f3863dd74a28cee869ea24fdc4ca8c2/specs/compliance/k8s-cis-1.23.yaml#L480))

Thus, we can use the information already present:

```
  - id: 3.1.2
    name: Ensure that the kubelet service file ownership is set to root:root (Manual)
    description: Ensure that the kubelet service file ownership is set to root:root
    checks:
      - id: AVD-KCV-0070
    severity: HIGH
```

- The `ID`, `name`, and `description` is taken directlly from the AWS EKS CIS Benchmarks
- The `check` and `severity` are taken from the existing Complaince check in the `k8s-cis-1.23.yaml`


**2. Manual description**

If the check does not already exist in the [Aqua Vulnerability Database](https://avd.aquasec.com/) (AVD) and thus, is not part of the trivy-policies, then the compliance check has to be populated with the information from the official definition.

Below is the beginning of the information of the EKS CIS Benchmarks v1.4.0:

![EKS Benchmarks 2.1.1](../../imgs/eks-benchmarks.png)

The corresponding check in the `control` section will look like this:

```
  - id: 2.1.1
    name: Enable audit Logs (Automated)
    description: |
      Control plane logs provide visibility into operation of the EKS Control plane components systems. 
      The API server audit logs record all accepted and rejected requests in the cluster. 
      When enabled via EKS configuration the control plane logs for a cluster are exported to a CloudWatch 
      Log Group for persistence.
    checks: null
    severity: MEDIUM
```

- Again, the `id`, `name` and `description` are taken directly from the EKS CIS Benchmarks v1.4.0
- The `checks` is in this case `null` as the check is not currently present in the AVD/as a Rego check in the checks directory in the [trivy policies](https://github.com/aquasecurity/trivy-policies/tree/main/checks)
- Since the check does not exist in Trivy, the `severity` will be `MEDIUM`. However, in some cases, the compliance report e.g. the CIS Benchmark report will specify the severity

### Test the Compliance Spec

To test the compliance check written on a local Kubernetes cluster, pass the new path into the Trivy scan through the `--compliance` flag:

```
trivy --compliance @</path/to/compliance.yaml> 
```

## Writing new Compliance Checks

To write new Rego checks for Trivy, please take a look at the contributing documentation for checks.