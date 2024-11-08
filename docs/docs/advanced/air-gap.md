# Advanced Network Scenarios

Trivy requires internet connectivity in order to function normally. If your organizations blocks or restricts network traffic, that could prevent Trivy from working correctly.
This document explains Trivy's network connectivity requirements, and how to configure Trivy to work in restricted networks environments, including completely air-gapped environments.

The following external resources are required by Trivy for the respective features:

External Resource | Feature | Details
--- | --- | ---
Vulnerability Database | Vulnerability scanning | [Trivy DB](../scanner/vulnerability.md)
Java Vulnerability Database | Java vulnerability scanning | [Trivy Java DB](../coverage/language/java.md)
Misconfigurations Database | Misconfigurations scanning | [Trivy Checks](../scanner/misconfiguration/check/builtin.md)
VEX Hub | VEX Hub | [VEX Hub](../supply-chain/vex/repo/#vex-hub)
Maven Central / Remote Repositories | Java vulnerability scanning | [Java Scanner/Remote Repositories](../coverage/language/java.md#remote-repositories)

!!! note
    Trivy is an open source project that relies on public free infrastructure. In case of extreme load, you may encounter rate limiting when Trivy attempts to connect to external resources.

The rest of this document details each resource's connectivity requirements and relevant configuration options.

## Vulnerability & Java databases

### Connectivity requirements

Trivy's Vulnerability and Java databases are packaged as OCI images and stored in public container registries. The specific registries and locations are detailed in the [databases document](../configuration/db.md).

Communication with OCI Registries follows the [OCI Distribution](https://github.com/opencontainers/distribution-spec) spec.

The following hosts are known to be used by the default container registries:

Registry | Hosts | Additional info
--- | --- | ---
GitHub Container Registry | <ul><li>`ghcr.io`</li><li>`pkg-containers.githubusercontent.com`</li></ul> | [GitHub's IP addresses](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses) 

### Self-hosting

You can host Trivy's databases in your own container registry. Please refer to [Self-hosting document](./self-hosting.md) for a detailed guide.

### Manual cache population

You can download the databases files manually and surgically populate the Trivy cache directory with them.

#### Downloading the DB files

On a machine with internet access, pull the database container archive from the public registry into your local workspace:

Note that these examples operate in the current working directory.

=== "Using ORAS"
    This example uses [ORAS](https://oras.land), but you can use any other container registry manipulation tool.

    ```shell
    oras pull ghcr.io/aquasecurity/trivy-db:2
    ```
    
    You should now have a file called `db.tar.gz`. Next, extract it to reveal the db files:
    
    ```shell
    tar -xzf db.tar.gz
    ```
    

=== "Using Trivy"
    This example uses Trivy to pull the database container archive. The `--cache-dir` flag makes Trivy download the database files into our current working directory. The `--download-db-only` flag tells Trivy to only download the database files, not to scan any images.
    
    ```shell
    trivy image --cache-dir . --download-db-only
    ```

You should now have 2 new files, `metadata.json` and `trivy.db`. These are the Trivy DB files, copy them over to the air-gapped environment.

#### Populating the Trivy Cache

In order to populate the cache, you need to identify the location of the cache directory. If it is under the default location, you can run the following command to find it:

```shell
trivy -h | grep cache
```

For the example, we will assume the `TRIVY_CACHE_DIR` variable holds the cache location:

```shell
TRIVY_CACHE_DIR=/home/user/.cache/trivy
```

Put the Trivy DB files in the Trivy cache directory under a `db` subdirectory:

```shell
# ensure cache db directory exists
mkdir -p ${TRIVY_CACHE_DIR}/db
# copy the db files
cp /path/to/trivy.db /path/to/metadata.json ${TRIVY_CACHE_DIR}/db/
```

#### Java DB adaptations

For Java DB the process is the same, except for the following:

1. Image location is `ghcr.io/aquasecurity/trivy-java-db:1`
2. Archive file name is `javadb.tar.gz`
3. DB file name is `trivy-java.db`

## Misconfiguration Checks Database

### Connectivity requirements

Trivy's misconfiguration database is packaged as an OCI image and follows the same connectivity requirements as the Vulnerability and Java databases, as can be seen [here](#vulnerability-java-databases).

### Self-hosting

You can host Trivy's databases in your own container registry. Please refer to [Self-hosting document](./self-hosting.md) for a detailed guide.

### Embedded misconfiguration database

Misconfigurations database is embedded in the Trivy binary (at build time), and will be used as a fallback if the external database is not available. This means that you can still scan for misconfigurations in an air-gapped environment using the database from the time of the Trivy release you are using.

## VEX Hub

### Connectivity Requirements

VEX Hub is fetched from VEX Hub GitHub Repository directly: <https://github.com/aquasecurity/vexhub>. Using simple HTTPS requests.

The following hosts are known to be used by GitHub's services:

- `api.github.com`
- `codeload.github.com`

For more information about GitHub connectivity (including specific IP addresses), please refer to [GitHub's connectivity troubleshooting guide](https://docs.github.com/en/get-started/using-github/troubleshooting-connectivity-problems).

### Self-hosting

You can host a copy of VEX Hub on your own internal server. Please refer to the [self-hosting document](./self-hosting.md) for a detailed guide.

## Maven Central / Remote Repositories

### Connectivity requirements

Trivy might attempt to connect to the following URLs:

- `https://repo.maven.apache.org/maven2`

### Offline mode

There's no way to leverage Maven Central in a network-restricted environment, but you can prevent Trivy from trying to connect to it by using the `--offline-scan` flag.
