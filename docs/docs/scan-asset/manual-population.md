# Manual Asset Population

Trivy uses a local cache directory to store the asset files, as described in the [cache](../configuration/cache.md) document.
You can download the asset files and surgically populate the Trivy cache directory with them.

## Vulnerability Database
### Downloading the Asset Files

On a machine with internet access, pull the asset archive from the public registry into your local workspace:

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
    This example uses Trivy to pull the database archive.
    The `--cache-dir` flag makes Trivy download the database files into our current working directory.
    The `--download-db-only` flag tells Trivy to only download the database files, not to scan any images.

    ```shell
    trivy image --cache-dir . --download-db-only
    ```

You should now have 2 new files, `metadata.json` and `trivy.db`. These are the Trivy DB files, copy them over to the environment where Trivy runs.

### Populating the Trivy Cache

In order to populate the cache, you need to identify the location of the cache directory.
If it is under the default location, you can run the following command to find it:

```shell
trivy -h | grep cache-dir
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

## Java DB adaptations

For Java DB the process is the same, except for the following:

1. Image location is `ghcr.io/aquasecurity/trivy-java-db:1`
2. Archive file name is `javadb.tar.gz`
3. DB file name is `trivy-java.db`
 
## Misconfiguration Checks Bundle

For checks bundle, the process is the same, except for the following:

1. Location is `ghcr.io/aquasecurity/trivy-checks:1`
2. Archive file name is `bundle.tar.gz`

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
