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

!!! note
    ARM template expressions (e.g. `[parameters('name')]`, `[concat(...)]`) are not evaluated.
    A property whose value is an expression is treated as if it were not set, so checks may produce
    inaccurate results for such properties. This is especially relevant for templates built from Bicep,
    where expressions are common.

## Secret
The secret scan is performed on plain text files, with no special treatment for Azure ARM templates.

[Misconfiguration]: ../../scanner/misconfiguration/index.md
[Secret]: ../../scanner/secret.md

[^1]: Bicep is not natively supported. It needs to be converted into Azure ARM templates.