## Packages that support vulnerability scanning
- [OS packages][os_packages]
- [Language-specific packages][language_packages]

## Other language-specific packages

| Language | File              | Dependency location[^1] |
|----------|-------------------|:-----------------------:|
| Python   | conda package[^2] |            -            |
| Swift    | Podfile.lock      |            -            |

[^1]: Use `startline == 1 and endline == 1` for unsupported file types
[^2]: `envs/*/conda-meta/*.json`

[os_packages]: ../vulnerability/detection/os.md
[language_packages]: ../vulnerability/detection/language.md
