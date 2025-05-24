# Usage Telemetry

Trivy collect anonymous usage data in order to help us improve the product. This document explains what is collected and how you can control it.

## Data collected

The following information could be collected:

- Environmental information
  - Installation identifier
  - Trivy version
  - Operating system
- Scan
  - Non-revealing scan options

## Privacy

No personal information, scan results, or sensitive data is specifically collected. We take the following measures to ensure that:

- Installation identifier: one-way hash of machine fingerprint, resulting in opaque string.
- Scaner: any option that is user controlled is omitted (never collected). For example, file paths, image names, etc are never collected.

Trivy is an Aqua Security product and adheres to the company's privacy policy: <https://aquasec.com/privacy>.

## Disabling telemetry

You can disable telemetry altogether using the `--disable-telemetry` flag. Like other Trivy flags, this can be set on the command line, YAML configuration file, or environment variable. For more details see [here](../configuration/index.md).

For example:

```bash
trivy image --disable-metrics alpine
```
