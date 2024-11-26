# Connectivity and Network considerations

Trivy requires internet connectivity in order to function normally. If your organizations blocks or restricts network traffic, that could prevent Trivy from working correctly.
This document explains Trivy's network connectivity requirements, and how to configure Trivy to work in restricted networks environments, including completely air-gapped environments.

The following table lists all external resources that are required by Trivy:

External Resource | Feature | Details
--- | --- | ---
Vulnerability Database | Vulnerability scanning | [Trivy DB](../scanner/vulnerability.md)
Java Vulnerability Database | Java vulnerability scanning | [Trivy Java DB](../coverage/language/java.md)
Checks Bundle | Misconfigurations scanning | [Trivy Checks](../scanner/misconfiguration/check/builtin.md)
VEX Hub | VEX Hub | [VEX Hub](../supply-chain/vex/repo/#vex-hub)
Maven Central / Remote Repositories | Java vulnerability scanning | [Java Scanner/Remote Repositories](../coverage/language/java.md#remote-repositories)

!!! note
    Trivy is an open source project that relies on public free infrastructure. In case of extreme load, you may encounter rate limiting when Trivy attempts to connect to external resources.

The rest of this document details each resource's connectivity requirements and network related considerations.

## OCI Databases

Trivy's Vulnerability, Java, and Checks Bundle are packaged as OCI images and stored in public container registries.

### Connectivity requirements

The specific registries and locations are detailed in the [databases document](../configuration/db.md).

Communication with OCI Registries follows the [OCI Distribution](https://github.com/opencontainers/distribution-spec) spec.

The following hosts are known to be used by the default container registries:

Registry | Hosts | Additional info
--- | --- | ---
Google Artifact Registry | <ul><li>`mirror.gcr.io`</li><li>`googlecode.l.googleusercontent.com`</li></ul> | [Google's IP addresses](https://support.google.com/a/answer/10026322?hl=en)
GitHub Container Registry | <ul><li>`ghcr.io`</li><li>`pkg-containers.githubusercontent.com`</li></ul> | [GitHub's IP addresses](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses)

### Self-hosting

You can host Trivy's databases in your own container registry. Please refer to [Self-hosting document](./self-hosting.md#oci-databases) for a detailed guide.

## Embedded Checks

Checks Bundle is embedded in the Trivy binary (at build time), and will be used as a fallback if the external database is not available. This means that you can still scan for misconfigurations in an air-gapped environment using the database from the time of the Trivy release you are using.

## VEX Hub

### Connectivity Requirements

VEX Hub is hosted as at <https://github.com/aquasecurity/vexhub>.

Trivy is fetching VEX Hub GitHub Repository directly using simple HTTPS requests.

The following hosts are known to be used by GitHub's services:

- `api.github.com`
- `codeload.github.com`

For more information about GitHub connectivity (including specific IP addresses), please refer to [GitHub's connectivity troubleshooting guide](https://docs.github.com/en/get-started/using-github/troubleshooting-connectivity-problems).

### Self-hosting

You can host a copy of VEX Hub on your own internal server. Please refer to the [self-hosting document](./self-hosting.md#vex-hub) for a detailed guide.

## Maven Central / Remote Repositories

Trivy might call out to Maven central or other remote repositories to fetch in order to correctly identify Java packages during a vulnerability scan.

### Connectivity requirements

Trivy might attempt to connect (over HTTPS) to the following URLs:

- `https://repo.maven.apache.org/maven2`

### Offline mode

There's no way to leverage Maven Central in a network-restricted environment, but you can prevent Trivy from trying to connect to it by using the `--offline-scan` flag.
