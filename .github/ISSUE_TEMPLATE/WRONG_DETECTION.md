---
name: Wrong Detection
labels: ["kind/security-advisory"]
about: If Trivy doesn't detect something, or shows false positive detection
---
<!--

Please, read the documentation before creating an issue:
https://aquasecurity.github.io/trivy/latest/community/contribute/issue/

-->

## Check Advisory Databases
- [ ] run Trivy with `-f json` that shows data sources. Please make sure that data source is correct.
- [ ] visit [Github Advisory Database](https://github.com/advisories) and search CVE-ID.
- [ ] visit [Gitlab Advisory Database](https://advisories.gitlab.com/) and search CVE-ID.

## Description

<!--
Briefly describe the CVE that aren't detected and information about artifacts with this CVE.
-->

## JSON Output of run with `-debug`:

```
(paste your output here)
```

## Output of `trivy -v`:

```
(paste your output here)
```

## Additional details (base image name, container registry info...):


