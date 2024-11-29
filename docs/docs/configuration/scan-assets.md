# Scan Assets

This document describes how to configure Trivy's scan asset management behavior.
While assets are automatically managed by default, there are various configuration options available for specific needs.

For details about the scan assets, see [Scan Assets](../scan-asset/index.md).

## Custom Locations

You can configure custom download locations for each asset:

| Asset            | Configuration Method         | Available Options                                                 |
|------------------|------------------------------|-------------------------------------------------------------------|
| Vulnerability DB | `--db-repository`            | [OCI Repositories](../scan-asset/index.md#vulnerability-database) |
| Java DB          | `--java-db-repository`       | [OCI Repositories](../scan-asset/index.md#java-index-database)    |
| Checks Bundle    | `--checks-bundle-repository` | [OCI Repositories](../scan-asset/index.md#checks-bundle)          |
| VEX Repository   | [repository.yaml][vex-repo]  | [Any VEX repositories][vex-repo]                                  |

For details about hosting options, see [Self-Hosting Assets](../scan-asset/self-hosting.md)

Example usage for OCI registry configuration:

``` bash
trivy image --db-repository registry.my-company.example/trivy-db:2 alpine:3.15
```

Multiple repositories can be specified as fallbacks for OCI assets:

```bash
trivy image --db-repository registry.my-company.example/trivy-db:2 --db-repository ghcr.io/aquasecurity/trivy-db:2 alpine:3.15
```

## Skip Updates

| Asset            | Skip Flag                | Description                         |
|------------------|--------------------------|-------------------------------------|
| Vulnerability DB | `--skip-db-update`       | Skip vulnerability database updates |
| Java DB          | `--skip-java-db-update`  | Skip Java database updates          |
| Checks Bundle    | `--skip-check-update`    | Skip policy bundle updates          |
| VEX Hub          | `--skip-vex-repo-update` | Skip VEX repository updates         |

For example,

```bash
trivy image --skip-db-update --skip-java-db-update debian:12
```

## Update Only Mode

| Asset            | Update Command/Flag       | Description                          |
|------------------|---------------------------|--------------------------------------|
| Vulnerability DB | `--download-db-only`      | Download vulnerability database only |
| Java DB          | `--download-java-db-only` | Download Java database only          |
| Checks Bundle    | N/A                       | No dedicated download-only flag      |
| VEX Hub          | `trivy vex repo download` | Download VEX data explicitly         |

For example,

```bash
trivy image --download-db-only
```

## Cache Cleanup
See [Clear Caches](./cache.md#clear-caches)

[vex-repo]: ../supply-chain/vex/repo.md