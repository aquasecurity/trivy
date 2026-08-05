# AppImage Scanning

Trivy can scan [AppImage](https://appimage.org/) files for vulnerabilities, secrets, and misconfigurations.
AppImage is a universal Linux application format that bundles an application and all its dependencies
into a self-contained executable. Internally, it embeds a SquashFS filesystem within an ELF binary.

!!! warning "Experimental"
    AppImage scanning is an experimental feature. Results may vary depending on the AppImage structure.

## Quick Start

```bash
$ trivy appimage /path/to/app.AppImage
```

## Supported Scanners

| Scanner         | Supported |
|----------------|-----------|
| Vulnerability  | ✅        |
| Misconfiguration | ✅      |
| Secret         | ✅        |
| License        | ✅        |

## How It Works

1. Trivy reads the ELF header of the AppImage to locate the embedded SquashFS payload.
2. The SquashFS filesystem is mounted in-memory using a pure-Go SquashFS reader.
3. All files within the SquashFS are walked and analyzed using Trivy's standard analysis pipeline.

!!! note "AppImage Type 2 only"
    Only AppImage Type 2 files (`AI\x02` magic at offset 8) are supported.
    Type 1 AppImages (based on ISO 9660) are not currently supported.

## Examples

```bash
# Scan for vulnerabilities and output a table
$ trivy appimage /path/to/app.AppImage

# Output as JSON
$ trivy appimage --format json /path/to/app.AppImage

# Scan only OS packages (not language-specific packages)
$ trivy appimage --pkg-types os /path/to/app.AppImage

# Scan with a specific vulnerability severity threshold
$ trivy appimage --severity HIGH,CRITICAL /path/to/app.AppImage

# Use client/server mode
$ trivy appimage --server http://localhost:4954 /path/to/app.AppImage
```

## Options

The `appimage` subcommand supports the same flags as `trivy fs` and `trivy vm`, excluding AWS-specific options.

Key flags:

| Flag | Description |
|------|-------------|
| `--scanners` | Comma-separated list of scanners: `vuln,misconfig,secret,license` |
| `--pkg-types` | Package types to scan: `os,library` |
| `--severity` | Filter by severity: `CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN` |
| `--format` | Output format: `table,json,sarif,cyclonedx,spdx` |
| `--ignore-unfixed` | Ignore vulnerabilities without a fix available |

Run `trivy appimage --help` for the full list.

## Comparison with `trivy fs`

`trivy fs` scans a directory on the local filesystem. `trivy appimage` extracts and scans
the SquashFS payload embedded in the AppImage without writing any files to disk.

## Limitations

- Large AppImages (>200 MB SquashFS) may be slower to scan.
- Type 1 AppImages not supported.
- Remote (EBS/AMI) AppImage scanning is not supported.
