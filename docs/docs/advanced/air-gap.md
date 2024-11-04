# Advanced Network Scenarios

Trivy needs to connect to the internet occasionally in order to download relevant content. This document explains the network connectivity requirements of Trivy and setting up Trivy in particular scenarios.

## Network requirements

Trivy's databases are distributed as OCI images via GitHub Container registry (GHCR), AWS Elastic Container Registry (ECR) or DockerHub:

- [AWS ECR](https://gallery.ecr.aws/aquasecurity): ``public.ecr.aws``
- [DockerHub](https://hub.docker.com/u/aquasec): ``index.docker.io``
- [GHCR](https://github.com/orgs/aquasecurity/packages): ``ghcr.io``

The following hosts are at least required in order to fetch them:

AWS ECR:
- `public.ecr.aws`

DockerHub:
- `index.docker.io`

GHCR:
- `ghcr.io`
- `pkg-containers.githubusercontent.com`

The databases are pulled by Trivy using the [OCI Distribution](https://github.com/opencontainers/distribution-spec) specification, which is a simple HTTPS-based protocol.

[VEX Hub](https://github.com/aquasecurity/vexhub) is distributed from GitHub over HTTPS.
The following hosts are required in order to fetch it:

- `api.github.com`
- `codeload.github.com`

## Running Trivy in air-gapped environment

An air-gapped environment refers to situations where the network connectivity from the machine Trivy runs on is blocked or restricted.

In an air-gapped environment it is your responsibility to update the Trivy databases on a regular basis. 

## Offline Mode

By default, Trivy will attempt to download latest databases. If it fails, the scan might fail. To avoid this behavior, you can tell Trivy to not attempt to download database files:

- `--skip-db-update` to skip updating the main vulnerability database.
- `--skip-java-db-update` to skip updating the Java vulnerability database.
- `--skip-check-update` to skip updating the misconfiguration database.

```shell
trivy image --skip-db-update --skip-java-db-update --offline-scan --skip-check-update myimage
```

## Self-Hosting

### OCI Databases

You can host the databases on your own local OCI registry. 

First, make a copy of the databases in a container registry that is accessible to Trivy. The databases are in:

- `ghcr.io/aquasecurity/trivy-db:2`
- `ghcr.io/aquasecurity/trivy-java-db:1`
- `ghcr.io/aquasecurity/trivy-checks:0`

Then, tell Trivy to use the local registry:

```shell
trivy image \
    --db-repository myregistry.local/trivy-db \
    --java-db-repository myregistry.local/trivy-java-db \
    --checks-bundle-repository myregistry.local/trivy-checks \
    myimage
```

#### Authentication

If the registry requires authentication, you can configure it as described in the [private registry authentication document](../advanced/private-registries/index.md).

### VEX Hub

You can host a copy of VEX Hub on your own internal server.

First, make a copy of VEX Hub in a location that is accessible to Trivy.

1. Download the [VEX Hub](https://github.com/aquasecurity/vexhub) archive from: <https://github.com/aquasecurity/vexhub/archive/refs/heads/main.zip>.
1. Download the [VEX Hub Repository Manifest](https://github.com/aquasecurity/vex-repo-spec#2-repository-manifest) file from: <https://github.com/aquasecurity/vexhub/blob/main/vex-repository.json>.
1. Create or identify an internal HTTP server that can serve the VEX Hub repository in your environment (e.g `https://server.local`).
1. Make the downloaded archive file available for serving from your server (e.g `https://server.local/main.zip`).
1. Modify the downloaded manifest file's [Location URL](https://github.com/aquasecurity/vex-repo-spec?tab=readme-ov-file#locations-subfields) field to the URL of the archive file on your server (e.g `url: https://server.local/main.zip`).
1. Make the manifest file available for serving from your server under the `/.well-known` path  (e.g `https://server.local/.well-known/vex-repository.json`).

Then, tell Trivy to use the local VEX Repository:

1. Locate your [Trivy VEX configuration file](../supply-chain/vex/repo/#configuration-file) by running `trivy vex repo init`. Make the following changes to the file.
1. Disable the default VEX Hub repo (`enabled: false`)
1. Add your internal VEX Hub repository as a [custom repository](../supply-chain/vex/repo/#custom-repositories) with the URL pointing to your local server (e.g `url: https://server.local`).

#### Authentication

If your server requires authentication, you can configure it as described in the [VEX Repository Authentication document](../supply-chain/vex/repo/#authentication).

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

Note that the misconfigurations checks bundle is also embedded in the Trivy binary (at build time), and will be used as a fallback if the external database is not available. This means that you can still scan for misconfigurations in an air-gapped environment using the Checks from the time of the Trivy release you are using.

The misconfiguration scanner can be configured to load checks from a local directory, using the `--config-check` flag. In an air-gapped scenario you can copy the checks library from [Trivy checks repository](https://github.com/aquasecurity/trivy-checks) into a local directory, and load it with this flag. See more in the [Misconfiguration scanner documentation](../scanner/misconfiguration/index.md).
