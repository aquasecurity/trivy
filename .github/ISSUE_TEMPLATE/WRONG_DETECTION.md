---
name: Wrong Detection
labels: ["kind/bug"]
about: If Trivy doesn't detect something, or shows false positive detection
---

## Checklist
- [ ] I've read [the documentation regarding wrong detection](https://aquasecurity.github.io/trivy/latest/community/contribute/issue/#wrong-detection).
- [ ] I've confirmed that a security advisory in data sources was correct.
    - Run Trivy with `-f json` that shows data sources and make sure that the security advisory is correct.


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


