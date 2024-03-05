# Contribute Compliance Checks in Trivy

Trivy supports several different compliance checks. The details on Compliance Scanning with Trivy are provided in the [Compliance documentation](../../docs/compliance/compliance.md).
All of the Compliance Checks currently available in Trivy can be found in the `trivy-policies/specs/compliance/` directory ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/specs/compliance)).

## Importing Compliance Frameworks from kube-bench

New checks are based on the Custom Compliance report detailed in the [main documentation.](../../docs/compliance/compliance/#custom-compliance)
kube-bench has been the defacto Compliance Scanner for Kubernetes workloads by mmany organisations. The Trivy community and maintainers are still working on importing Compliance Checks from kube-bench into Trivy and expanding the number of checks available.

This section details how community members can contribute compliance checks.

The Kube-Bench Checks can be found under `kube-bench/cfg` ([Link](https://github.com/aquasecurity/kube-bench/tree/main/cfg)).

### Create a new Compliance Spec

The existing compliance checks in Trivy are located under the `trivy-policies/specis/compliance/` directory ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/specs/compliance)).

Create a new file under `trivy-policies/specs/compliance/` and name the file in the format of "provider-specktype-version". For ecample AWS CIS Benchmarks version 1.5: `k8s-eks-1.4.yaml`.

### Minimum spec structure

The structure of the Compliance Check is detailed in the main documentation. For example:

```
spec:
  id: k8s-eks-1.4
  title: AWS EKS Benchmarks v1.4
  description: AWS EKS Benchmarks
  version: "1.4"
  relatedResources:
  - https://www.cisecurity.org/benchmark/amazon_web_services
  controls:
  - id: 2.1.3
    name: require-mfa-delete
    description: Buckets should have MFA deletion protection enabled.
    checks:
    - id: AVD-AWS-0170
    severity: LOW
```

The first section in the spec is focused on the metadata of the spec. Replace all the fields of the metadata with the information relevant to the Compliance Spec you want to add.

- `id` -- This is the same name as the file
- `title` -- A short title of the spec
- `description` -- This can be a longer description of the compliance spec
- `version` -- The compliance spec version that the Compliance Check targets. For instance, for CIS Benchmarks version 1.5, the version will be `1.5`.
- `relatedResources` -- Any resources that relate to this Compliance Check and can provide users with more information in the future.

The second section details all of the checks that make up the Compliance Check. These checks are detailed under `controls`.

  - `id` -- has to be the ID from the official Compliance Documentation such as the CIS Benchmark version
  - `name` --  is the name of the check in short format
  - `description` -- Is a description of how the resource should be configured.
  - `checks.id` -- is the AVD ID, more information provided below.
  - `severity` -- is the severity as detailed in the official Compliance Documentation such as the CIS Benchmark version

#### Populating the `control` section

Compliance checks detail a set of checks that should pass so that the resource is compliant with the benchmark specifications. There are two ways in which Trivy Compliance Checks can enforce the Compliance Specification.

**1. Referencing the check that is already part of Trivy.**

Trivy has a comprehensive list of checks as part of its misconfiguration scanning. These can be found in the `trivy-policies/checks` directory ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/checks)). If the check is present, the AVD_ID and other information from the check has to be used.

**2. Manual description**

If the check does not already exist in the [Aqua Vulnerability Database](https://avd.aquasec.com/) (AVD) and thus, is not part of the trivy-policies, then the Compliance Check has to be populated with the information from the official definition. For instance, CIS Benchmarks can be downloaded from the [main site.]() An example is provided below.

Below is the beginning of the information of the EKS CIS Benchmarks v1.4.0:

![EKS Benchmarks 2.1.1](../../imgs/eks-benchmarks.png)

The corresponding check in the `control` section will look like this:

```
  - id: 2.1.1
    text: "Enable audit Logs (Automated)"
    type: "manual"
    remediation: |
      Control plane logs provide visibility into operation of the EKS Control plane components ystems. 
      The API server audit logs record all accepted and rejected requests in the cluster. 
      When enabled via EKS configuration the control plane logs for a cluster are exported to a CloudWatch 
      Log Group for persistence.
    scored: false
```

### Test the Compliance Spec

To test the Compliance Check written on a local Kubernetes cluster, pass the new path into the trivy scan through the `--compliance` flag:

```
trivy --compliance @</path/to/compliance.yaml> 
```

## Writing new Compliance Checks

To write new Compliance Checks that reference Rego checks which are not yet in 