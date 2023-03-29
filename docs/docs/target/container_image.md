# Container Image

Trivy supports two targets for container images.

- Files inside container images
- Container image metadata

## Files inside container images
Container images consist of files.
For instance, new files will be installed if you install a package.

Trivy scans the files inside container images for

- Vulnerabilities
- Misconfigurations
- Secrets
- Licenses

By default, vulnerability and secret scanning are enabled, and you can configure that with `--scanners`.

### Vulnerabilities
It is enabled by default.
You can simply specify your image name (and a tag).
It detects known vulnerabilities in your container image.
See [here](../vulnerability/scanning.md) for the detail.

```
$ trivy image [YOUR_IMAGE_NAME]
```

For example:

```
$ trivy image python:3.4-alpine
```

<details>
<summary>Result</summary>

```
2019-05-16T01:20:43.180+0900    INFO    Updating vulnerability database...
2019-05-16T01:20:53.029+0900    INFO    Detecting Alpine vulnerabilities...

python:3.4-alpine3.9 (alpine 3.9.2)
===================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| openssl | CVE-2019-1543    | MEDIUM   | 1.1.1a-r1         | 1.1.1b-r1     | openssl: ChaCha20-Poly1305     |
|         |                  |          |                   |               | with long nonces               |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
```

</details>

To enable only vulnerability scanning, you can specify `--scanners vuln`.

```shell
$ trivy image --scanners vuln [YOUR_IMAGE_NAME]
```

### Misconfigurations
It is supported, but it is not useful in most cases.
As mentioned [here](../misconfiguration/scanning.md), Trivy mainly supports Infrastructure as Code (IaC) files for misconfigurations.
If your container image includes IaC files such as Kubernetes YAML files or Terraform files, you should enable this feature with `--scanners config`.

```
$ trivy image --scanners config [YOUR_IMAGE_NAME]
```

### Secrets
It is enabled by default.
See [here](../secret/scanning.md) for the detail.

```shell
$ trivy image [YOUR_IMAGE_NAME]
```

### Licenses
It is disabled by default.
See [here](../licenses/scanning.md) for the detail.

```shell
$ trivy image --scanners license [YOUR_IMAGE_NAME]
```

## Container image metadata
Container images have [configuration](https://github.com/opencontainers/image-spec/blob/2fb996805b3734779bf9a3a84dc9a9691ad7efdd/config.md).
`docker inspect` and `docker history` show the information according to the configuration.

Trivy scans the configuration of container images for

- Misconfigurations
- Secrets

They are disabled by default.
You can enable them with `--image-config-scanners`.
 
!!! tips
    The configuration can be exported as the JSON file by `docker save`.

### Misconfigurations
Trivy detects misconfigurations on the configuration of container images.
The image config is converted into Dockerfile and Trivy handles it as Dockerfile.
See [here](../misconfiguration/scanning.md) for the detail of Dockerfile scanning.

It is disabled by default.
You can enable it with `--image-config-scanners config`.

```
$ trivy image --image-config-scanners config [YOUR_IMAGE_NAME]
```

If you just want to scan the image config, you can disable scanners with `--scanners none`.
For example:

```
$ trivy image --scanners none --image-config-scanners config alpine:3.17.0
```

<details>
<summary>Result</summary>

```
alpine:3.17 (dockerfile)
========================
Tests: 24 (SUCCESSES: 21, FAILURES: 3, EXCEPTIONS: 0)
Failures: 3 (UNKNOWN: 0, LOW: 2, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: Specify at least 1 USER command in Dockerfile with non-root user as argument
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

See https://avd.aquasec.com/misconfig/ds002
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


LOW: Consider using 'COPY file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /' command instead of 'ADD file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /'
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.

See https://avd.aquasec.com/misconfig/ds005
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 alpine:3.17:1
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1 [ ADD file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


LOW: Add HEALTHCHECK instruction in your Dockerfile
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
You shoud add HEALTHCHECK instruction in your docker container images to perform the health check on running containers.

See https://avd.aquasec.com/misconfig/ds026
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
</details>

!!! tip
    You can see how each layer is created with `docker history`.

### Secrets
Trivy detects secrets on the configuration of container images.
The image config is converted into JSON and Trivy scans the file for secrets.
It is especially useful for environment variables that are likely to have credentials by accident.
See [here](../secret/scanning.md) for the detail.

```shell
$ trivy image --image-config-scanners secret [YOUR_IMAGE_NAME]
```

If you just want to scan the image config, you can disable scanners with `--scanners none`.
For example:

```shell
$ trivy image --scanners none --image-config-scanners secret vuln-image
```

<details>
<summary>Result</summary>

```
vuln-image (alpine 3.17.1)
==========================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)


vuln-image (secrets)
====================
Total: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 2)

CRITICAL: GitHub (github-pat)
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
GitHub Personal Access Token
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 test:16
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  14     {
  15     "created": "2023-01-09T17:05:20Z",
  16 [   "created_by": "ENV secret=****************************************",
  17     "comment": "buildkit.dockerfile.v0",
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


CRITICAL: GitHub (github-pat)
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
GitHub Personal Access Token
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 test:34
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  32     "Env": [
  33     "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  34 [   "secret=****************************************"
  35     ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

</details>

!!! tip
    You can see environment variables with `docker inspect`.

## Supported
### Docker Engine
Trivy tries to looks for the specified image in your local Docker Engine.
It will be skipped if Docker Engine is not running locally.

If your docker socket is not the default path, you can override it via `DOCKER_HOST`.

### containerd

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.
    
Trivy tries to looks for the specified image in your local [containerd](https://containerd.io/).
It will be skipped if containerd is not running locally.

Specify your image name in containerd running locally.

```bash
$ nerdctl images
REPOSITORY        TAG       IMAGE ID        CREATED         PLATFORM       SIZE         BLOB SIZE
aquasec/nginx    latest    2bcabc23b454    3 hours ago     linux/amd64    149.1 MiB    54.1 MiB
$ trivy image aquasec/nginx
```

If your containerd socket is not the default path (`//run/containerd/containerd.sock`), you can override it via `CONTAINERD_ADDRESS`.

```bash
$ export CONTAINERD_ADDRESS=/run/k3s/containerd/containerd.sock
$ trivy image aquasec/nginx
```

If your scan targets are images in a namespace other than containerd's default namespace (`default`), you can override it via `CONTAINERD_NAMESPACE`.

```bash
$ export CONTAINERD_NAMESPACE=k8s.io
$ trivy image aquasec/nginx
```

### Podman

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Scan your image in Podman (>=2.0) running locally. The remote Podman is not supported.
Before performing Trivy commands, you must enable the podman.sock systemd service on your machine.
For more details, see [here](https://github.com/containers/podman/blob/master/docs/tutorials/remote_client.md#enable-the-podman-service-on-the-server-machine).


```bash
$ systemctl --user enable --now podman.socket
```

Then, you can scan your image in Podman.

```bash
$ cat Dockerfile
FROM alpine:3.12
RUN apk add --no-cache bash
$ podman build -t test .
$ podman images
REPOSITORY                TAG     IMAGE ID      CREATED      SIZE
localhost/test            latest  efc372d4e0de  About a minute ago  7.94 MB
$ trivy image test
```

### Container Registry
Trivy supports registries that comply with the following specifications.

- [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)

You can configure credentials with `docker login`.
See [here](../advanced/private-registries/index.md) for the detail.

### Tar Files
Trivy supports image tar files generated by the following tools.

- [Docker Image Specification](https://github.com/moby/moby/tree/master/image/spec)
    - [Moby Project](https://github.com/moby/moby/)
    - [Buildah](https://github.com/containers/buildah)
    - [Podman](https://github.com/containers/podman)
    - [img](https://github.com/genuinetools/img)
- [Kaniko](https://github.com/GoogleContainerTools/kaniko)

```
$ docker pull ruby:3.1-alpine3.15
$ docker save ruby:3.1-alpine3.15 -o ruby-3.1.tar
$ trivy image --input ruby-3.1.tar
```

<details>
<summary>Result</summary>

```
2022-02-03T10:08:19.127Z        INFO    Detected OS: alpine
2022-02-03T10:08:19.127Z        WARN    This OS version is not on the EOL list: alpine 3.15
2022-02-03T10:08:19.127Z        INFO    Detecting Alpine vulnerabilities...
2022-02-03T10:08:19.127Z        INFO    Number of language-specific files: 2
2022-02-03T10:08:19.127Z        INFO    Detecting gemspec vulnerabilities...
2022-02-03T10:08:19.128Z        INFO    Detecting node-pkg vulnerabilities...
2022-02-03T10:08:19.128Z        WARN    This OS version is no longer supported by the distribution: alpine 3.15.0
2022-02-03T10:08:19.128Z        WARN    The vulnerability detection may be insufficient because security updates are not provided

ruby-3.1.tar (alpine 3.15.0)
============================
Total: 3 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 3, CRITICAL: 0)

+----------+------------------+----------+-------------------+---------------+---------------------------------------+
| LIBRARY  | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+----------+------------------+----------+-------------------+---------------+---------------------------------------+
| gmp      | CVE-2021-43618   | HIGH     | 6.2.1-r0          | 6.2.1-r1      | gmp: Integer overflow and resultant   |
|          |                  |          |                   |               | buffer overflow via crafted input     |
|          |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-43618 |
+----------+                  +          +                   +               +                                       +
| gmp-dev  |                  |          |                   |               |                                       |
|          |                  |          |                   |               |                                       |
|          |                  |          |                   |               |                                       |
+----------+                  +          +                   +               +                                       +
| libgmpxx |                  |          |                   |               |                                       |
|          |                  |          |                   |               |                                       |
|          |                  |          |                   |               |                                       |
+----------+------------------+----------+-------------------+---------------+---------------------------------------+

Node.js (node-pkg)
==================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)


Ruby (gemspec)
==============
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```

</details>

### OCI Layout
Trivy supports image directories compliant with [Open Container Image Layout Specification](https://github.com/opencontainers/image-spec/blob/master/spec.md).

Buildah:

```
$ buildah push docker.io/library/alpine:3.11 oci:/path/to/alpine
$ trivy image --input /path/to/alpine
```

Skopeo:

```
$ skopeo copy docker-daemon:alpine:3.11 oci:/path/to/alpine
$ trivy image --input /path/to/alpine
```

## SBOM
Trivy supports the generation of Software Bill of Materials (SBOM) for container images and the search for SBOMs during vulnerability scanning.

### Generation
Trivy can generate SBOM for container images.
See [here](../sbom/index.md) for the detail.

### Discovery
Trivy can search for Software Bill of Materials (SBOMs) that reference container images.
If an SBOM is found, the vulnerability scan is performed using the SBOM instead of the container image.
By using the SBOM, you can perform a vulnerability scan more quickly, as it allows you to skip pulling the container image and analyzing its layers.

To enable this functionality, you need to specify the `--sbom-sources` flag.
The following two sources are supported:

- OCI Registry (`oci`)
- Rekor (`rekor`)

Example:

```bash
$ trivy image --sbom-sources oci ghcr.io/knqyf263/oci-referrers
2023-03-05T17:36:55.278+0200    INFO    Vulnerability scanning is enabled
2023-03-05T17:36:58.103+0200    INFO    Detected SBOM format: cyclonedx-json
2023-03-05T17:36:58.129+0200    INFO    Found SBOM (cyclonedx) in the OCI referrers
...

ghcr.io/knqyf263/oci-referrers (alpine 3.16.2)
==============================================
Total: 17 (UNKNOWN: 0, LOW: 0, MEDIUM: 5, HIGH: 9, CRITICAL: 3)
```

The OCI Registry utilizes the [Referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers).
For more information about Rekor, please refer to [its documentation](../attestation/rekor.md).

## Compliance

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

This section describes container image specific compliance reports.
For an overview of Trivy's Compliance feature, including working with custom compliance, check out the [Compliance documentation](../compliance/compliance.md).

### Built in reports

The following reports are available out of the box:

| Compliance                             | Version | Name for command | More info                                                                                   |
|----------------------------------------|---------|------------------|---------------------------------------------------------------------------------------------|
| CIS Docker Community Edition Benchmark | 1.1.0   | `docker-cis`     | [Link](https://www.aquasec.com/cloud-native-academy/docker-container/docker-cis-benchmark/) |

### Examples

Scan a container image configuration and generate a compliance summary report:

```
$ trivy image --compliance docker-cis [YOUR_IMAGE_NAME]
```

!!! note
    The `Issues` column represent the total number of failed checks for this control.

## Authentication
Please reference [this page](../advanced/private-registries/index.md).

## Options
### Scan Image on a specific Architecture and OS
By default, Trivy loads an image on a "linux/amd64" machine.
To customise this, pass a `--platform` argument in the format OS/Architecture for the image:

```
$ trivy image --platform=os/architecture [YOUR_IMAGE_NAME]
```

For example:

```
$ trivy image --platform=linux/arm alpine:3.16.1
```

<details>
<summary>Result</summary>

```
2022-10-25T21:00:50.972+0300    INFO    Vulnerability scanning is enabled
2022-10-25T21:00:50.972+0300    INFO    Secret scanning is enabled
2022-10-25T21:00:50.972+0300    INFO    If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2022-10-25T21:00:50.972+0300    INFO    Please see also https://aquasecurity.github.io/trivy/dev/docs/secret/scanning/#recommendation for faster secret detection
2022-10-25T21:00:56.190+0300    INFO    Detected OS: alpine
2022-10-25T21:00:56.190+0300    INFO    Detecting Alpine vulnerabilities...
2022-10-25T21:00:56.191+0300    INFO    Number of language-specific files: 0

alpine:3.16.1 (alpine 3.16.1)
=============================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)

┌─────────┬────────────────┬──────────┬───────────────────┬───────────────┬─────────────────────────────────────────────────────────────┐
│ Library │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                            Title                            │
├─────────┼────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│ zlib    │ CVE-2022-37434 │ CRITICAL │ 1.2.12-r1         │ 1.2.12-r2     │ zlib: heap-based buffer over-read and overflow in inflate() │
│         │                │          │                   │               │ in inflate.c via a...                                       │
│         │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2022-37434                  │
└─────────┴────────────────┴──────────┴───────────────────┴───────────────┴─────────────────────────────────────────────────────────────┘
```

</details>

