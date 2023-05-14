# Compliance Reports

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy’s compliance flag lets you curate a specific set of checks into a report. In a typical Trivy scan, there are hundreds of different checks for many different components and configurations, but sometimes you already know which specific checks you are interested in. Often this would be an industry accepted set of checks such as CIS, or some vendor specific guideline, or your own organization policy that you want to comply with. These are all possible using the flexible compliance infrastructure that's built into Trivy. Compliance reports are defined as simple YAML documents that select checks to include in the report.

## Usage

Compliance report is currently supported in the following targets (trivy sub-commands):

- `trivy image`
- `trivy aws`
- `trivy k8s`

Add the `--compliance` flag to the command line, and set it's value to desired report.
For example: `trivy k8s cluster --compliance k8s-nsa` (see below for built-in and custom reports)

### Options

The following flags are compatible with `--compliance` flag and allows customizing it's output:

| flag               | effect                                                                               |
|--------------------|--------------------------------------------------------------------------------------|
| `--report summary` | shows a summary of the results. for every control shows the number of failed checks. |
| `--report all`     | shows fully detailed results. for every control shows where it failed and why.       |
| `--format table`   | shows results in textual table format (good for human readability).                  |
| `--format json`    | shows results in json format (good for machine readability).                         |

## Built-in compliance

Trivy has a number of built-in compliance reports that you can asses right out of the box.
to specify a built-in compliance report, select it by ID like `trivy --compliance <compliance_id>`.

For the list of built-in compliance reports, please see the relevant section:

- [Docker compliance](../target/container_image.md#compliance)
- [Kubernetes compliance](../target/kubernetes.md#compliance) 
- [AWS compliance](../target/aws.md#compliance)

## Custom compliance

You can create your own custom compliance report. A compliance report is a simple YAML document in the following format:

```yaml
spec:
  id: "k8s-myreport" # report unique identifier. this should not container spaces.
  title: "My custom Kubernetes report" # report title. Any one-line title.
  description: "Describe your report" # description of the report. Any text.
  relatedResources :
    - https://some.url # useful references. URLs only.
  version: "1.0" # spec version (string)
  controls:
    - name: "Non-root containers" # Name for the control (appears in the report as is). Any one-line name.
      description: 'Check that container is not running as root' # Description (appears in the report as is). Any text.
      id: "1.0" # control identifier (string)
      checks:   # list of existing Trivy checks that define the control
        - id: AVD-KSV-0012 # check ID. Must start with `AVD-` or `CVE-` 
      severity: "MEDIUM" # Severity for the control (note that checks severity isn't used)
    - name: "Immutable container file systems"
      description: 'Check that container root file system is immutable'
      id: "1.1"
      checks:
        - id: AVD-KSV-0014
      severity: "LOW"
```

The check id field (`controls[].checks[].id`) is referring to existing check by it's "AVD ID". This AVD ID is easily located in the check's source code metadata header, or by browsing [Aqua vulnerability DB](https://avd.aquasec.com/), specifically in the [Misconfigurations](https://avd.aquasec.com/misconfig/) and [Vulnerabilities](https://avd.aquasec.com/nvd) sections.

Once you have a compliance spec, you can select it by file path: `trivy --compliance @</path/to/compliance.yaml>` (note the `@` indicating file path instead of report id).
