# Scanning Coverage
Trivy can detect security issues in many different platforms, languages and configuration files.
This section gives a general overview of that coverage, and can help answer the frequently asked question "Does Trivy support X?".
For more detailed information about the specific platforms and languages, check the relevant documentation.

- [OS Packages](os/index.md)
- [Language-specific Packages](language/index.md)
- [IaC files](iac/index.md)
- [Kubernetes clusters](./kubernetes.md)

## Packages Detection Behavior
Trivy prioritizes precision in package and version detection, aiming to minimize false positives while potentially accepting some false negatives.
This approach is particularly relevant in two key areas:

- Handling Software Installed via OS Packages
- Handling Packages with Unspecified Versions

### Handling Software Installed via OS Packages
Files installed by OS package managers, such as `apt`, Trivy doesn’t analyze as language-specific packages (e.g., Python packages, Java JAR files).  
This means that even if a library file (e.g., a JAR or Python package) is present in a container image, if it was installed via an OS package manager (e.g., `apt`),  
Trivy will not analyze the file (scan for vulnerabilities, include it in the SBOM, etc.).

For example, consider the Python `requests` package in Red Hat Universal Base Image 8:

```bash
[root@987ee49dc93d /]# head -n 3 /usr/lib/python3.6/site-packages/requests-2.20.0-py3.6.egg-info/PKG-INFO
Metadata-Version: 2.1
Name: requests
Version: 2.20.0
```

Version 2.20.0 is installed, and this package is installed by `dnf`.

```bash
[root@987ee49dc93d /]# rpm -ql python3-requests | grep PKG-INFO
/usr/lib/python3.6/site-packages/requests-2.20.0-py3.6.egg-info/PKG-INFO
```

Red Hat may have backported fixes to v2.20.0-3, making the package different from the upstream PyPI version.

- Upstream (PyPI [requests]): Contains original v2.20.0
- Red Hat (`python-requests`): May contain backported fixes in v2.20.0-3

To ensure accurate package detection and avoid inconsistencies, Trivy trusts the OS vendor’s package information for software installed via OS package managers and doesn’t analyze the underlying files separately.

However, this approach may result in missing package information.  
In such cases, using [--detection-priority comprehensive](#detection-priority) allows Trivy to analyze the underlying files, giving more complete coverage, though it may cause inconsistencies.

### Handling Packages with Unspecified Versions
When a package version cannot be uniquely determined (e.g., `package-a: ">=3.0"`), Trivy typically skips detection for that package to avoid inaccurate results.
If a lock file is present with fixed versions, Trivy will use those.

To detect packages even with unspecified versions, use [--detection-priority comprehensive](#detection-priority).
This option makes Trivy use the minimum version in the specified range.
While this may lead to inaccuracies if the actual version used is not the minimum, it helps provide more comprehensive coverage.

## Detection Priority

Trivy provides a `--detection-priority` flag to control the balance between precision and comprehensiveness in package detection.
This concept affects how Trivy handles package identification and version determination.

```bash
$ trivy image --detection-priority {precise|comprehensive} alpine:3.15
```

- `precise`: This mode prioritizes accuracy in package detection. It results in cleaner package lists but may miss some packages or version information.
- `comprehensive`: This mode aims to detect more packages and versions, potentially including some that might be inaccurate.
  It provides broader coverage but may include inconsistent information.

The default value is `precise`. Also refer to the [detection behavior](#packages-detection-behavior) section for more information.

Regardless of the chosen mode, user review of detected packages is important:

- `precise`: Review thoroughly, considering potentially missed packages.
- `comprehensive`: Carefully verify package information due to possible inaccuracies.

[requests]: https://pypi.org/project/requests/