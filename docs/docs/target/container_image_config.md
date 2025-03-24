# Container Image Configuration

Scan a container image, local or remote. Scans the [configuration](https://github.com/opencontainers/image-spec/blob/2fb996805b3734779bf9a3a84dc9a9691ad7efdd/config.md) that defines the container image (you can examine it using the `docker save` command).

In addition to scanning the configuration of the container image, Trivy can also scan the contents of the image. For more info, see the [Image](./container_image.md) page.

`image` is a post-build target type, which means it scans installed packages. For more information, see [Target types](../coverage/language/index.md#target-types).

Usage:

```shell
trivy image --image-config-scanners misconfig,secret localimage:tag
trivy image --image-config-scanners misconfig,secret myregistry.io/myimage:tag
```

## Scanners

Supported scanners:

- Misconfigurations
- Secrets

By default, no image misconfiguration scanners are enabled. You can configure which scanners are used with the [`--image-config-scanners` flag](../configuration/others.md#enabledisable-scanners).

## Misconfiguration scanning

For misconfiguration scanning, the image config is converted into Dockerfile and Trivy scans it as Dockerfile.

!!! tip
    You can see how each layer is created with `docker history`.

The following checks are disabled for this scan type due to known issues:

| Check ID | Reason | Issue |
|----------|------------|--------|
| [AVD-DS-0007](https://avd.aquasec.com/misconfig/dockerfile/general/avd-ds-0007/) | This check detects multiple `ENTRYPOINT` instructions in a stage, but since image history analysis does not identify stages, this check is not relevant for this scan type. | [#8364](https://github.com/aquasecurity/trivy/issues/8364) |
| [AVD-DS-0016](https://avd.aquasec.com/misconfig/dockerfile/general/avd-ds-0016/) | This check detects multiple `CMD` instructions in a stage, but since image history analysis does not identify stages, this check is not relevant for this scan type. | [#7368](https://github.com/aquasecurity/trivy/issues/7368) |

## Secret scanning

For secret scanning, the image config is converted into JSON and Trivy scans the file for secrets.

!!! tip
    You can see environment variables with `docker inspect`.
