# Scan Assets

When you install Trivy, the installed artifact contains the scanner engine but is lacking relevant security information needed to make security detections and recommendations.
These so called "scan assets" are automatically fetched and maintained by Trivy as needed, so normally you shouldn't notice or worry about them.
This document elaborates on the scan assets mechanism and its configuration options.

A scan asset is defined as a resource that is transparently downloaded and cached by Trivy during scanning operations.

Trivy relies on the following assets:

| Asset              | Artifact name   | Contents                                                            | Purpose                                              |
|--------------------|-----------------|---------------------------------------------------------------------|------------------------------------------------------|
| Vulnerabilities DB | `trivy-db`      | CVE information collected from various feeds                        | used only for vulnerability scanning                 |
| Java Index DB      | `trivy-java-db` | Index of Java artifacts and their hash digest                       | used to identify Java artifacts only in JAR scanning |
| Checks Bundle      | `trivy-checks`  | Logic of misconfiguration checks                                    | used only in misconfiguration/IaC scanning           |
| VEX Hub            | `vexhub`        | Repository of Vulnerability Exploitability Exchange (VEX) documents | used for VEX processing                              |

!!! note
    This is not an exhaustive list of Trivy's external connectivity requirements.
    There are additional external resources which may be required by specific Trivy features.
    To learn about external connectivity requirements, see the Advanced Network Scenarios.

## Scanner Dependencies
Each scanner in Trivy may require different scan assets.
Assets are downloaded only when needed by the enabled scanners:

| Asset            | [SBOM][sbom][^1] | [Vulnerability][vuln] | [Misconfiguration][misconfig] | [Secret][secret] | [License][license] |
|------------------|------------------|-----------------------|-------------------------------|------------------|--------------------|
| Vulnerability DB | -                | ✅                     | -                             | -                | -                  |
| Java DB          | ✅[^2]            | ✅[^2]                 | -                             | -                | -                  |
| Checks Bundle    | -                | -                     | ✅                             | -                | -                  |
| VEX Hub          | -                | ✅[^3]                 | -                             | -                | -                  |

## Development

All scan assets are developed as open source software, just like Trivy itself.
Each asset is maintained in its own repository under the Aqua Security organization on GitHub:

| Asset            | Repository                                                                    |
|------------------|-------------------------------------------------------------------------------|
| Vulnerability DB | [aquasecurity/trivy-db](https://github.com/aquasecurity/trivy-db)             |
| Java DB          | [aquasecurity/trivy-java-db](https://github.com/aquasecurity/trivy-java-db)   |
| Checks Bundle    | [aquasecurity/trivy-policies](https://github.com/aquasecurity/trivy-policies) |
| VEX Hub          | [aquasecurity/vexhub](https://github.com/aquasecurity/vexhub)                 |

## Distribution
The scan assets are distributed through different protocols depending on their type and purpose:

| Asset            | Protocol                 |
|------------------|--------------------------|
| Vulnerability DB | [OCI][distribution-spec] |
| Java Index DB    | [OCI][distribution-spec] |
| Checks Bundle    | [OCI][distribution-spec] |
| VEX Hub          | HTTP                     |

## Locations
OCI artifacts (Vulnerability DB, Java DB, and Checks Bundle) are officially published to the following registries:

- GitHub Container Registry (GHCR)
- Docker Hub
- AWS Public ECR

Additionally, these artifacts can be pulled from `mirror.gcr.io`, which provides a cached mirror of Docker Hub artifacts for improved availability.

### Vulnerability Database
The vulnerability database is hosted on the following locations:

| Priority  | Registry                 | Artifact Address                       | Link                                          |
|-----------|--------------------------|----------------------------------------|-----------------------------------------------|
| Primary   | Google Artifact Registry | mirror.gcr.io/aquasec/trivy-db:2       | N/A                                           |
| Secondary | GHCR                     | ghcr.io/aquasecurity/trivy-db:2        | https://ghcr.io/aquasecurity/trivy-db         |
| -         | Docker Hub               | docker.io/aquasec/trivy-db:2           | https://hub.docker.com/r/aquasec/trivy-db     |
| -         | AWS ECR Public           | public.ecr.aws/aquasecurity/trivy-db:2 | https://gallery.ecr.aws/aquasecurity/trivy-db |


### Java Index Database

| Priority  | Registry                 | Artifact Address                            | Link                                               |
|-----------|--------------------------|---------------------------------------------|----------------------------------------------------|
| Primary   | Google Artifact Registry | mirror.gcr.io/aquasec/trivy-java-db:1       | N/A                                                |
| Secondary | GHCR                     | ghcr.io/aquasecurity/trivy-java-db:1        | https://ghcr.io/aquasecurity/trivy-java-db         |
| -         | Docker Hub               | docker.io/aquasec/trivy-java-db:1           | https://hub.docker.com/r/aquasec/trivy-java-db     |
| -         | AWS ECR Public           | public.ecr.aws/aquasecurity/trivy-java-db:1 | https://gallery.ecr.aws/aquasecurity/trivy-java-db |

### Checks Bundle

| Priority | Registry                 | Artifact Address                           | Link                                              |
|----------|--------------------------|--------------------------------------------|---------------------------------------------------|
| Primary  | GHCR                     | ghcr.io/aquasecurity/trivy-checks:1        | https://ghcr.io/aquasecurity/trivy-checks         |
| -        | Google Artifact Registry | mirror.gcr.io/aquasec/trivy-checks:1       | N/A                                               |
| -        | Docker Hub               | docker.io/aquasec/trivy-checks:1           | https://hub.docker.com/r/aquasec/trivy-checks     |
| -        | AWS ECR Public           | public.ecr.aws/aquasecurity/trivy-checks:1 | https://gallery.ecr.aws/aquasecurity/trivy-checks |

### VEX Hub

| Priority | Location | Link                                   |
|----------|----------|----------------------------------------|
| Primary  | GitHub   | https://github.com/aquasecurity/vexhub |


## Update Process

| Component        | Build Method   | Build Frequency | Cache Update Frequency[^4] |
|------------------|----------------|-----------------|----------------------------|
| Vulnerability DB | GitHub Actions | Every 6 hours   | Every 24 hours             |
| Java Index DB    | GitHub Actions | Daily           | Every 7 days               |
| Checks Bundle    | GitHub Actions | As needed       | Every 24 hours             |
| VEX Hub          | Git Repository | As needed       | Every 24 hours             |


[sbom]: ../supply-chain/sbom.md
[vuln]: ../scanner/vulnerability.md
[misconfig]: ../scanner/misconfiguration/index.md
[secret]: ../scanner/secret.md
[license]: ../scanner/license.md

[trivy-db]: https://github.com/aquasecurity/trivy-db
[distribution-spec]: https://github.com/opencontainers/distribution-spec
[vexhub]: ../supply-chain/vex/repo.md

[^1]: SBOM is not a scanner but an output format option
[^2]: Only required for Java artifact scanning
[^3]: Only required when [VEX processing is enabled][vexhub]
[^4]: Cache Update Frequency indicates how often Trivy client checks for updates and refreshes its local cache. This process happens automatically in the background during scans.
