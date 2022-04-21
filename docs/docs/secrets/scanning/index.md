# Secrets Scanning

Trivy scans any filesystem and image to detect exposed secrets.

Secret scanning is enabled by default using the [`filesystem`][fs] or [`image`][image] subcommands.

Trivy will scan every plaintext file, according to builtin rules or configuration.

## Configuration
Trivy has a set of builtin rules for secret scanning, wich can be extended or modified by custom [configuration] file.

[image]: image.md
[fs]: filesystem.md
[configuration]: ../configuration.md
