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

By default, only vulnerability and secret scanning are enabled. You can configure which scanners are used with the [`--scanners` flag](https://trivy.dev/latest/docs/configuration/others/#enabledisable-scanners).
