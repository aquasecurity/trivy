# Air-Gapped Environments and Self-Hosting

When you install Trivy, the installed artifact contains the scanner engine but is lacking relevant security information needed to make security detections and recommendations. These so called "databases" are fetched and maintained by Trivy automatically as needed.

If your organizations blocks or restricts network traffic (from the machine Trivy runs on), Trivy might not be able to download the databases from public repositories.

This document explains how handle such advanced connectivity scenarios.

!!! note
    Please familiarize yourself with the [Databases document](../configuration/db.md) that explains about the different databases used by Trivy and the different configuration options that control them. This guide assumes you are already familiar with the concepts explained there.

## Self-Hosting

You can host Trivy's databases in a container registry that is accessible to Trivy.

First, make a copy of the databases into your container registry. The different databases, their use cases, and their locations are detailed in the [Trivy Databases](../configuration/db.md) document.

 !!! note
    You will need to keep the databases updated in order to maintain relevant scanning results.

Then, tell Trivy to use the local registry using the relevant flags.

For example, we if we scan a Java application, we copy the `trivy-db` and `trivy-java-db` databases to our local registry and tell Trivy to use them. In this case we also need to turn off Trivy's [Java scanner external service](../coverage/language/java.md) with the `--offline-scan` flag:

```shell
trivy image \
    --db-repository myregistry.local/trivy-db \
    --java-db-repository myregistry.local/trivy-java-db \
    --offline-scan \
    myimage
```

### Registry Authentication

If the registry requires authentication, you can configure it as described in the [private registry authentication document](../advanced/private-registries/index.md).

### Pull through cache

You can install a pull-through cache service inside your environment that automatically serves consecutive pulls from cache instead of reaching the origin.  
Here are some examples for pull-through cache solutions:

- [Docker Registry](https://docs.docker.com/docker-hub/mirror/)
- [Harbor](https://goharbor.io/docs/2.1.0/administration/configure-proxy-cache/)
- [Zot](https://zotregistry.dev/v2.1.0/articles/mirroring)
- [AWS ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/pull-through-cache.html) 

## Manual cache population

You can also download the databases files manually and surgically populate the Trivy cache directory with them.

### Downloading the DB files

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

You should now have 2 new files, `metadata.json` and `trivy.db`. These are the Trivy DB files.

=== "Using Trivy"
This example uses Trivy to pull the database container archive. The `--cache-dir` flag makes Trivy download the database files into our current working directory. The `--download-db-only` flag tells Trivy to only download the database files, not to scan any images.

```shell
trivy image --cache-dir . --download-db-only
```

You should now have 2 new files, `metadata.json` and `trivy.db`. These are the Trivy DB files, copy them over to the air-gapped environment.

### Populating the Trivy Cache

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

### Java DB

For Java DB the process is the same, except for the following:

1. Image location is `ghcr.io/aquasecurity/trivy-java-db:1`
2. Archive file name is `javadb.tar.gz`
3. DB file name is `trivy-java.db`

## Misconfigurations scanning

Misconfigurations checks are also embedded in the Trivy binary (at build time), and will be used as a fallback if the external database is not available. This means that you can still scan for misconfigurations in an air-gapped environment using the Checks from the time of the Trivy release you are using.

## VEX Hub

You can host a copy of VEX Hub on your own internal server.

First, make a copy of VEX Hub in a location that is accessible to Trivy.

1. Download the [VEX Hub](https://github.com/aquasecurity/vexhub) archive from: <https://github.com/aquasecurity/vexhub/archive/refs/heads/main.zip>.
1. Download the [VEX Hub Repository Manifest](https://github.com/aquasecurity/vex-repo-spec#2-repository-manifest) file from: <https://github.com/aquasecurity/vexhub/blob/main/vex-repository.json>.
1. Create or identify an internal HTTP server that can serve the VEX Hub repository in your environment (e.g `https://server.local`).
1. Make the downloaded archive file available for serving from your server (e.g `https://server.local/main.zip`).
1. Modify the downloaded manifest file's [Location URL](https://github.com/aquasecurity/vex-repo-spec?tab=readme-ov-file#locations-subfields) field to the URL of the archive file on your server (e.g `url: https://server.local/main.zip`).
1. Make the manifest file available for serving from your server under the `/.well-known` path  (e.g `https://server.local/.well-known/vex-repository.json`).

Then tell Trivy to use the local VEX Repository:

1. Locate your [Trivy VEX configuration file](../supply-chain/vex/repo/#configuration-file) by running `trivy vex repo init`. Make the following changes to the file.
1. Disable the default VEX Hub repo (`enabled: false`)
1. Add your internal VEX Hub repository as a [custom repository](../supply-chain/vex/repo/#custom-repositories) with the URL pointing to your local server (e.g `url: https://server.local`).

### VEX Hub Authentication

If your server requires authentication, you can configure it as described in the [VEX Repository Authentication document](../supply-chain/vex/repo/#authentication).
