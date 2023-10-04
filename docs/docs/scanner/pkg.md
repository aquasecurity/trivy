# Package scanning
Trivy scans any container image, filesystem and git repository to find installed packages.

The following packages are supported.

- [OS packages](../coverage/os/index.md#supported-os)
- [Language-specific packages](../coverage/language/index.md#supported-languages)

## Quick start
This section shows how to find all installed packages in container image and filesystem. Other subcommands should be the same.

Specify an image name with `--scanners pkg` and format.

!!! Note
    `--scanners pkg` does not work in `table` format. Use other [formats][supported-formats] to get all installed packages.

!!! Warning
    Trivy separates language specific packages to `pre-build` and `post-build`.
    To select the correct `target` - see [this page][supported-languages].

```bash
$ trivy image --scanners pkg -f json alpine:3.18.3
{
  ...(snip)...
  "Results": [
    {
      "Target": "alpine:3.18.3 (alpine 3.18.3)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Packages": [
        {
          "ID": "alpine-baselayout@3.4.3-r1",
          "Name": "alpine-baselayout",
          "Version": "3.4.3-r1",
          "Arch": "x86_64",
          "SrcName": "alpine-baselayout",
          "SrcVersion": "3.4.3-r1",
          "Licenses": [
            "GPL-2.0"
          ],
          "DependsOn": [
            "alpine-baselayout-data@3.4.3-r1",
            "busybox-binsh@1.36.1-r2"
          ],
          "Layer": {
            "Digest": "sha256:7264a8db6415046d36d16ba98b79778e18accee6ffa71850405994cffa9be7de",
            "DiffID": "sha256:4693057ce2364720d39e57e85a5b8e0bd9ac3573716237736d6470ec5b7b7230"
          },
          "Digest": "sha1:cf0bca32762cd5be9974f4c127467b0f93f78f20"
        },
        {
          "ID": "alpine-baselayout-data@3.4.3-r1",
          "Name": "alpine-baselayout-data",
          "Version": "3.4.3-r1",
          "Arch": "x86_64",
          "SrcName": "alpine-baselayout",
          "SrcVersion": "3.4.3-r1",
          "Licenses": [
            "GPL-2.0"
          ],
          "Layer": {
            "Digest": "sha256:7264a8db6415046d36d16ba98b79778e18accee6ffa71850405994cffa9be7de",
            "DiffID": "sha256:4693057ce2364720d39e57e85a5b8e0bd9ac3573716237736d6470ec5b7b7230"
          },
          "Digest": "sha1:602007ee374ed96f35e9bf39b1487d67c6afe027"
        },
        ...(snip)...
      ]
    }
  ]
}
```

[supported-formats]: ../configuration/reporting.md#supported-formats
[supported-languages]: ../coverage/language/index.md#supported-languages