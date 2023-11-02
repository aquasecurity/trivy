# CloudFormation
Trivy supports the scanners listed in the table below.

|      Scanner       | Supported |
|:------------------:|:---------:|
| [Misconfiguration] |     ✓     |
|      [Secret]      |     ✓     |

It supports the following formats.

| Format | Supported |
|:------:|:---------:|
|  JSON  |     ✓     |
|  YAML  |     ✓     |

## Misconfiguration
Trivy recursively searches directories and scans all found CloudFormation files.
It evaluates properties, functions, and other elements within CloudFormation files to detect misconfigurations.

### Value Overrides
You can provide `cf-params` with path to [CloudFormation Parameters] file to Trivy to scan your CloudFormation code with parameters.

```bash
trivy conf --cf-params params.json ./infrastructure/cf
```

## Secret
The secret scan is performed on plain text files, with no special treatment for CloudFormation.

[Misconfiguration]: ../../scanner/misconfiguration/index.md
[Secret]: ../../scanner/secret.md
[CloudFormation Params]: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html