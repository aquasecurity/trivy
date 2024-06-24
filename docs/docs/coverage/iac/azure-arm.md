# Azure ARM Template
Trivy supports the scanners listed in the table below.

|      Scanner       | Supported |
| :----------------: | :-------: |
| [Misconfiguration] |     ✓     |
|      [Secret]      |     ✓     |

It supports the following configurations:

|    Format    | Supported |
| :----------: | :-------: |
| ARM template |     ✓     |
|    Bicep     |   ✓[^1]   |

To scan Bicep codes, you need to convert them into ARM templates first.

```
az bicep build -f main.bicep
or
bicep build main.bicep
```

## Misconfiguration
Trivy recursively searches directories and scans all found Azure ARM templates.

## Secret
The secret scan is performed on plain text files, with no special treatment for Azure ARM templates.

[Misconfiguration]: ../../scanner/misconfiguration/index.md
[Secret]: ../../scanner/secret.md

[^1]: Bicep is not natively supported. It needs to be converted into Azure ARM templates.