# Kubernetes
Trivy supports the scanners listed in the table below.

|      Scanner       | Supported |
| :----------------: | :-------: |
| [Misconfiguration] |     ✓     |
|      [Secret]      |     ✓     |

In addition to raw YAML and JSON, it supports the following templates:

|    Template     | Supported |
| :-------------: | :-------: |
| [Helm](helm.md) |     ✓     |
|    Kustomize    |   ✓[^1]   |

!!! note
    Trivy does not support Kustomize overlays, so it scans files defined in the base.
    Or, you can scan the output of `kustomize build`.

## Misconfiguration
Trivy recursively searches directories and scans all found Kubernetes files.

## Secret
The secret scan is performed on plain text files, with no special treatment for Kubernetes.
This means that Base64 encoded secrets are not scanned, and only secrets written in plain text are detected.


[Misconfiguration]: ../../scanner/misconfiguration/index.md
[Secret]: ../../scanner/secret.md

[^1]: Kustomize is not natively supported.