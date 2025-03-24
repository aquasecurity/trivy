# Rootfs

Scan a filesystem. This is typically used for scanning:

- Scan host machine
- [Scan container](../advanced/container/embed-in-dockerfile.md)
- [Scan unpacked container filesystem](../advanced/container/unpacked-filesystem.md)

`rootfs` is a post-build target type, which means it scans installed packages. For more information, see [Target types](../coverage/language/index.md#target-types).

Usage:

```shell
trivy rootfs /path/to/fs
```

## Scanners

Supported scanners:

- Vulnerabilities
- Misconfigurations
- Secrets
- Licenses

By default, only vulnerability and secret scanning are enabled. You can configure which scanners are used with the [`--scanners` flag](../configuration/others.md#enabledisable-scanners).

## Avoiding full filesystem traversal

By default, Trivy traverses all files from the specified root directory to find target files for scanning.
However, when you only need to scan specific files with absolute paths, you can avoid this traversal, which makes scanning faster.
For example, when scanning only OS packages, no full traversal is performed:

```bash
trivy rootfs --pkg-types os --scanners vuln /
```

When scanning language-specific packages or secrets, traversal is necessary because the location of these files is unknown.
If you want to exclude specific directories from scanning for better performance, you can use the [--skip-dirs](../configuration/skipping.md) option.
