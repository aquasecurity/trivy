# Trivy Databases

When you install Trivy, the installed artifact contains the scanner engine but is lacking relevant security information needed to make security detections and recommendations. These so called "databases" are fetched and maintained by Trivy automatically as needed, so normally you shouldn't notice or worry about them. However, some situations might require your attention to Trivy's network connectivity. This section elaborates on the database management mechanism and it's configuration options.

Trivy relies on the following databases:

DB | Artifact name | Contents | Purpose
--- | --- | --- | ---
Vulnerabilities DB | `trivy-db` | CVE information collected from various feeds | used only for [vulnerability scanning](../scanner/vulnerability.md)
Java DB | `trivy-java-db` | Index of Java artifacts and their hash digest | used to identify Java artifacts only in [Java vulnerability scanning](../coverage/language/java.md)
Misconfiguration DB | `checks-db` | Logic of misconfiguration checks | used only in [misconfiguration/IaC scanning](../scanner/misconfiguration/check/builtin.md)
VEX Hub | `vex-hub` | VEX statements | Used only in [VEX Hub is enabled](../supply-chain/vex/repo.md) in vulnerability scanning.

## External Services

In addition to the above, some specific scanning features might connect to external services, and have different connectivity requirements and configuration options. This document discusses only Trivy's own databases, but for your convenience here are use cases where external services are involved:

- [Java vulnerability scanning](../coverage/language/java.md).

## Locations

Following are official locations of Trivy databases:

| Registry | Image Address | Link
| --- | --- | ---
| GHCR | `ghcr.io/aquasecurity/trivy-db:2` | <https://ghcr.io/aquasecurity/trivy-db>
| | `ghcr.io/aquasecurity/trivy-java-db` | <https://ghcr.io/aquasecurity/trivy-java-db>
| | `aquaghcr.io/aquasecurity/ecurity/trivy-checks` | <https://ghcr.io/aquasecurity/trivy-checks>
| Docker Hub | `aquasec/trivy-db:2` | <https://hub.docker.com/r/aquasec/trivy-db>
| | `aquasec/trivy-java-db:1` | <https://hub.docker.com/r/aquasec/trivy-java-db>
| AWS ECR | `public.ecr.aws/aquasecurity/trivy-db:2` | <https://gallery.ecr.aws/aquasecurity/trivy-db>
| | `public.ecr.aws/aquasecurity/trivy-java-db:1` | <https://gallery.ecr.aws/aquasecurity/trivy-java-db>

 VEX Hub is fetched from VEX Hub GitHub Repository directly: <https://github.com/aquasecurity/vexhub>.

### Automatic fallback

Trivy will attempt to pull images from the official registries in the order specified. In case of failure of pulling a database, Trivy will fall back to the next alternative registry in the order specified.  
You can specify additional alternative repositories as explained in the [configuring database locations section](#locations).

The Checks Database registry location option does not support fallback through multiple options. This is because in case of a failure pulling the checks-db, Trivy will use the embedded checks as a fallback.

## Connectivity requirements

| database | location | protocol | hosts
| --- | --- | --- | ---
| <ul><li>`trivy-db`</li><li>`trivy-java-db`</li><li>`checks-db`</li></ul> | GHCR | [OCI Distribution](https://github.com/opencontainers/distribution-spec) over HTTPS | <ul><li>`ghcr.io`</li><li>`pkg-containers.githubusercontent.com`</li></ul>
| `vexhub`| GitHub | Git over HTTPS | <ul><li>`api.github.com`</li><li>`codeload.github.com`</li></ul>

For more information about GitHub connectivity (including specific IP addresses), please refer to [GitHub's connectivity troubleshooting guide](https://docs.github.com/en/get-started/using-github/troubleshooting-connectivity-problems).

### Rate limiting

Trivy is an open source project that relies on public free infrastructure. In case of extreme load, you may encounter rate limiting when Trivy attempts to update its databases. If you are facing rate-limiting issues:

1. Consider self-hosting the databases, or implementing a proxy-cache in your organization.
2. Look into specific registry rate-limiting policies which might provide solution for your use-case (for example by authenticating with the registry).
3. Consider using a commercial service that provides the full [Aqua platform](https://www.aquasec.com/products/software-supply-chain-security/), which includes a stable and reliable scanning service.

## DB Management Configuration

### Database Locations

You can configure Trivy to download databases from alternative locations by using the flags:

- `--db-repository`
- `--java-db-repository`
- `--checks-bundle-repository`

The value should be an image address in a container registry.

For example:

```
trivy image --db-repository registry.gitlab.com/gitlab-org/security-products/dependencies/trivy-db alpine
```

The `--db-repository` flag accepts multiple values, which can be used to specify multiple alternative repository locations. In case of failure, Trivy will fall back to alternative registries in the order specified. An attempt to download from the next repository is only made if a temporary error is received (e.g. status 429 or 5xx).

For example:

```
trivy image --db-repository my.registry.local/trivy-db,registry.gitlab.com/gitlab-org/security-products/dependencies/trivy-db alpine
```

!!! note 
    Setting the repository location flags override the default values which include the official db locations. In case you want to preserve the default locations, you should include them in the list the you set as repository locations.

!!!note
    When pulling `trivy-db` or `trivy-java-db`, if image tag is not specified, Trivy defaults to the db schema number instead of the `latest` tag.

VEX Hub repository locations can be configured separately using the [VEX configuration file](../supply-chain/vex/repo.md)

### Skip updates

You can configure Trivy to not attempt to download database at all using the flags:

- `--skip-db-update`
- `--skip-java-db-update`
- `--skip-check-update`

For example:

```
trivy image --skip-db-update --skip-java-db-update --offline-scan --skip-check-update myimage
```

### Only update

You can ask `Trivy` to update the database without performing a scan using the flags:

- `--download-db-only`
- `--download-java-db-only`

For example:

```
trivy image --download-db-only
```

### Remove Databases

`trivy clean` command removes caches and databases.
You can select which cache component to remove:

option | description
--- | ---
`-a`/`--all` | remove all caches
`--checks-bundle` | remove checks bundle
`--java-db` | remove Java database
`--scan-cache` | remove scan cache (container and VM image analysis results)
`--vex-repo` | remove VEX repositories
`--vuln-db` | remove vulnerability database

Example:

```
$ trivy clean --vuln-db --java-db
2024-06-24T11:42:31+06:00       INFO    Removing vulnerability database...
2024-06-24T11:42:31+06:00       INFO    Removing Java database...
```

## Self-Hosting

You can host all of Trivy's databases on your own local environment (to prevent external connectivity). For more information, refer to the [Air-Gapped Environments and Self-Hosting](../advanced/air-gap.md) document.

When serving, proxying, or manipulating Trivy's databases, note that the media type of the OCI layer is not a standard container image type.

DB | Media Type | Reference
--- | --- | ---
`trivy-db` | `application/vnd.aquasec.trivy.db.layer.v1.tar+gzip` | <https://github.com/aquasecurity/trivy-db/pkgs/container/trivy-db>
`trivy-java-db` | `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` | https://github.com/aquasecurity/trivy-java-db/pkgs/container/trivy-java-db
