# CloudFormation
Trivy supports the scanners listed in the table below.

|      Scanner       | Supported |
| :----------------: | :-------: |
| [Misconfiguration] |     ✓     |
|      [Secret]      |     ✓     |

It supports the following formats.

| Format | Supported |
| :----: | :-------: |
|  JSON  |     ✓     |
|  YAML  |     ✓     |

## Misconfiguration
Trivy recursively searches directories and scans all found CloudFormation files.
It evaluates properties, functions, and other elements within CloudFormation files to detect misconfigurations.

## Secret
The secret scan is performed on plain text files, with no special treatment for CloudFormation.

[Misconfiguration]: ../../scanner/misconfiguration/index.md
[Secret]: ../../scanner/secret.md