# Compliance Reports

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy’s compliance flag lets you curate a specific set of checks into one report. In a typical Trivy scan, we make hundreds of different checks for many different components and configurations, but sometimes you already know which specific set of checks that you want to verify. Often this would be an industry accepted set of checks such as CIS, or some vendor specific guideline, or your own organization policy that you want to comply with. These are all possible using the flexible compliance infrastructure that's built into Trivy. Compliance reports are defined as simple YAML documents that select checks to add to the report.

## Built-in compliance

Trivy has a number of built-in compliance reports that you can asses right out of the box.
to specify a built-in compliance report, select it by name like `trivy --compliance <compliance_name>`.
These are described under each specific target, for example:

- [Kubernetes compliance](../kubernetes/cli/compliance.md) 
- [AWS compliance](../cloud/aws/compliance.md)

## Custom compliance

You can create custom compliance specification. Create a compliance spec, and select it by file path like `trivy --compliance @</path/to/compliance.yaml>` (note the `@` indicating file path instead of report name).

### Compliance spec format

```yaml
spec:
  id: "0001" # report unique identifier
  title: nsa # report title 
  description: "National Security Agency - Kubernetes Hardening Guidance" # description of the report
  relatedResources :
    - https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/ # reference is related to public or internal spec
  version: "1.0" # spec version
  controls:
    - name: "Non-root containers" # short control naming
      description: 'Check that container is not running as root' # long control description
      id: "1.0" # control identifier 
      checks:   # list of trivy checks which associated to control
        - id: AVD-KSV-0012 # check ID (midconfiguration ot vulnerability) must start with `AVD-` or `CVE-` 
      severity: "MEDIUM" # control severity
    - name: "Immutable container file systems"
      description: 'Check that container root file system is immutable'
      id: "1.1"
      checks:
        - id: AVD-KSV-0014
      severity: "LOW"
```

The check id field (`controls[].checks[].id`) is referencing an existing check by it's "AVD ID". This is easily located in the check's source code metadata header, or by browsing checks in [Aqua vulnerability DB](https://avd.aquasec.com/), specifically in the [Misconfigurations](https://avd.aquasec.com/misconfig/) and [Vulnerabilities](https://avd.aquasec.com/nvd) sections.
