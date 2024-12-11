# Self-Hosting Trivy's Databases

This document explains how to host Trivy's [external dependencies](./air-gap.md) in your own infrastructure to prevent external network access. If you haven't already, please familiarize yourself with the [Databases document](../configuration/db.md) that explains about the different databases used by Trivy and the different configuration options that control them. This guide assumes you are already familiar with the concepts explained there.

## OCI databases

The following [Trivy Databases](../configuration/db.md) are packaged as OCI images:

- `trivy-db`
- `trivy-java-db`
- `trivy-checks`

To host these databases in your own infrastructure:

### Make a local copy

Use any container registry manipulation tool (e.g , [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane.md, [ORAS](https://oras.land), [regclient](https://github.com/regclient/regclient/tree/main)) to copy the images to your destination registry.

!!! note
    You will need to keep the databases updated in order to maintain relevant scanning results over time.

### Configure Trivy

Use the appropriate [database location flags](../configuration/db.md#database-locations) to change the db-repository location:

- `--db-repository`
- `--java-db-repository`
- `--checks-bundle-repository`

### Authentication

If the registry requires authentication, you can configure it as described in the [private registry authentication document](../advanced/private-registries/index.md).

### OCI Media Types

When serving, proxying, or manipulating Trivy's databases, note that the media type of the OCI layer is not a standard container image type:

DB | Media Type | Reference
--- | --- | ---
`trivy-db` | `application/vnd.aquasec.trivy.db.layer.v1.tar+gzip` | <https://github.com/aquasecurity/trivy-db/pkgs/container/trivy-db>
`trivy-java-db` | `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` | https://github.com/aquasecurity/trivy-java-db/pkgs/container/trivy-java-db
`trivy-checks` | `application/vnd.oci.image.manifest.v1+json` | https://github.com/aquasecurity/trivy-checks/pkgs/container/trivy-checks

## Manual cache population

Trivy uses a local cache directory to store the database files, as described in the [cache](../configuration/cache.md) document.
You can download the databases files and surgically populate the Trivy cache directory with them.

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

### Java DB adaptations

For Java DB the process is the same, except for the following:

1. Image location is `ghcr.io/aquasecurity/trivy-java-db:1`
2. Archive file name is `javadb.tar.gz`
3. DB file name is `trivy-java.db`

## VEX Hub

### Make a local copy

To make a copy of VEX Hub in a location that is accessible to Trivy.

1. Download the [VEX Hub](https://github.com/aquasecurity/vexhub) archive from: <https://github.com/aquasecurity/vexhub/archive/refs/heads/main.zip>.
1. Download the [VEX Hub Repository Manifest](https://github.com/aquasecurity/vex-repo-spec#2-repository-manifest) file from: <https://github.com/aquasecurity/vexhub/blob/main/vex-repository.json>.
1. Create or identify an internal HTTP server that can serve the VEX Hub repository in your environment (e.g `https://server.local`).
1. Make the downloaded archive file available for serving from your server (e.g `https://server.local/main.zip`).
1. Modify the downloaded manifest file's [Location URL](https://github.com/aquasecurity/vex-repo-spec?tab=readme-ov-file#locations-subfields) field to the URL of the archive file on your server (e.g `url: https://server.local/main.zip`).
1. Make the manifest file available for serving from your server under the `/.well-known` path  (e.g `https://server.local/.well-known/vex-repository.json`).

### Configure Trivy

To configure Trivy to use the local VEX Repository:

1. Locate your [Trivy VEX configuration file](../supply-chain/vex/repo/#configuration-file) by running `trivy vex repo init`. Make the following changes to the file.
1. Disable the default VEX Hub repo (`enabled: false`)
1. Add your internal VEX Hub repository as a [custom repository](../supply-chain/vex/repo/#custom-repositories) with the URL pointing to your local server (e.g `url: https://server.local`).

### Authentication

If your server requires authentication, you can configure it as described in the [VEX Repository Authentication document](../supply-chain/vex/repo/#authentication).
