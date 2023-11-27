# Docker
Trivy supports the scanners listed in the table below.

|      Scanner       | Supported |
| :----------------: | :-------: |
| [Misconfiguration] |     ✓     |
|      [Secret]      |     ✓     |

It supports the following configurations.

|    Config     | Supported |
| :-----------: | :-------: |
|  Dockerfile   |     ✓     |
| Containerfile |     ✓     |
|    Compose    |     -     |

## Misconfiguration
Trivy recursively searches directories and scans all found Docker files.

## Secret
The secret scan is performed on plain text files, with no special treatment for Dockerfile.

[Misconfiguration]: ../../scanner/misconfiguration/index.md
[Secret]: ../../scanner/secret.md