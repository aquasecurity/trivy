# Self-Hosting Trivy's Databases

When you install Trivy, the installed artifact contains the scanner engine but is lacking relevant security information needed to make security detections and recommendations. These so called "databases" are fetched and maintained by Trivy automatically as needed.

If you prefer, you can host Trivy's databases in your own infrastructure. This document explains how to do that.

!!! note
    Please familiarize yourself with the [Databases document](../configuration/db.md) that explains about the different databases used by Trivy and the different configuration options that control them. This guide assumes you are already familiar with the concepts explained there.

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
`trivy-chekcs` | `application/vnd.oci.image.manifest.v1+json` | https://github.com/aquasecurity/trivy-checks/pkgs/container/trivy-checks

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
