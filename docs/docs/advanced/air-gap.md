# Air-Gapped Environment
Trivy needs to connect to the internet to download databases. If you are running Trivy in an air-gapped environment, or an tightly controlled network, this document will explain your options.
In an air-gapped environment it is your responsibility to update the Trivy databases on a regular basis, so that the scanner can detect newly disclosed vulnerabilities.  

## Network requirements
Trivy's Databases are distributed as OCI images via GitHub Container registry (GHCR):

- <https://ghcr.io/aquasecurity/trivy-db>
- <https://ghcr.io/aquasecurity/trivy-java-db>
- <https://ghcr.io/aquasecurity/trivy-checks>

If Trivy is running behind a firewall, you'll need to add the following urls to your allowlist:

- `ghcr.io`
- `pkg-containers.githubusercontent.com`

The databases are pulled by Trivy using the [OCI Distribution](https://github.com/opencontainers/distribution-spec) specification, which is based on simple HTTPS protocol.

## Running Trivy in air-gapped environment
In an air-gapped environment, you have to tell Trivy on every scan to not attempt to download the latest database files, otherwise the scan will fail. The following flags are relevant:

- `--skip-db-update` to skip updating the main vulnerability database.
- `--skip-java-db-update` to skip updating the Java vulnerability database.
- `--offline-scan` to scan Java applications without issuing API requests.
- `--skip-check-update` to skip updating the misconfiguration database.

```shell
trivy image --skip-db-update --skip-java-db-update --offline-scan --skip-check-update myimage
```

## Self-Hosting
You can also host the databases on your own OCI registry, in order to avoid having Trivy reaching out of your network.  

First, make a copy of the databases in a container registry that is accessible to Trivy. The databases are in:
- `ghcr.io/aquasecurity/trivy-db:2`
- `ghcr.io/aquasecurity/trivy-java-db:1`
-  `ghcr.io/aquasecurity/trivy-checks:0`

Then, tell Trivy to use the private images:

```shell
trivy image \
    --db-repository myregistry.local/trivy-db \
    --java-db-repository myregistry.local/trivy-java-db \
    --offline-scan \
    --checks-bundle-repository myregistry.local/trivy-checks \
    myimage
```

### Authentication

For Trivy DB, configure it in the [same way as for private images](../advanced/private-registries/index.md).

For Java DB, you need to run `docker login YOUR_REGISTRY`. Currently, specifying a username and password is not supported.

## Manual cache population
You can also download the databases files manually and surgically populate the Trivy cache directory with them.

### Downloading the DB files
On a machine with internet access, pull the database container archive from the registry into your local workspace:

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
trivy --cache-dir . image --download-db-only
```

You should now have 2 new files, `metadata.json` and `trivy.db`. These are the Trivy DB files.

### Populating the Trivy Cache
Once you obtained the Trivy DB files (`metadata.json` and `trivy.db`), copy them over to the air-gapped environment.

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

Note that the misconfigurations database is also embedded in the Trivy binary (at build time), and will be used as a fallback if the external database is not available. This means that you can still scan for misconfigurations in an air-gapped environment using the Checks from the time of the Trivy release you are using.

[allowlist]: ../references/troubleshooting.md#error-downloading-vulnerability-db
[oras]: https://oras.land/docs/installation

