# Rootfs
Rootfs scanning is for special use cases such as

- Host machine
- [Root filesystem](../advanced/container/embed-in-dockerfile.md)
- [Unpacked filesystem](../advanced/container/unpacked-filesystem.md)
 
```bash
$ trivy rootfs /path/to/rootfs
```

!!! note
    Rootfs scanning works differently from the Filesystem scanning.
    You should use `trivy fs` to scan your local projects in CI/CD.
    See [here](../scanner/vulnerability.md) for the differences.

!!! note
    Scanning vulnerabilities for `Red Hat` has a limitation, see the [Red Hat](../coverage/os/rhel.md#content-manifests) page for details.

## Performance Optimization

By default, Trivy traverses all files from the specified root directory to find target files for scanning.
However, when you only need to scan specific files with absolute paths, you can avoid this traversal, which makes scanning faster.
For example, when scanning only OS packages, no full traversal is performed:

```bash
$ trivy rootfs --pkg-types os --scanners vuln /
```

When scanning language-specific packages or secrets, traversal is necessary because the location of these files is unknown.
If you want to exclude specific directories from scanning for better performance, you can use the [--skip-dirs](../configuration/skipping.md) option.
