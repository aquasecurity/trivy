---
name: Wrong Detection
labels: ["kind/security-advisory"]
about: If Trivy doesn't detect something, or shows false positive detection
---
<!--

Trivy depends on Github Advisory Database and Gitlab Advisory Database. 
Sometime they have mistakes.

there is a small guide how to fix such mistakes: https://aquasecurity.github.io/trivy/latest/community/contribute/issue/

If the data source is correct and Trivy shows wrong results, please raise an issue on Trivy
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


