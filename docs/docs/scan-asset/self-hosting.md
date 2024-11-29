# Self-Hosting Assets

This document explains how to host Trivy's [scan assets][assets] in your own infrastructure to prevent external network access.
If you haven't already, please familiarize yourself with the [Scan Assets document][assets] that explains about the different assets used by Trivy and the different configuration options that control them.
This guide assumes you are already familiar with the concepts explained there.

## OCI Artifacts

The following assets are packaged as OCI artifacts:

- Vulnerability DB
- Java Index DB
- Checks Bundle

To host these assets in your own infrastructure:

### Make a local copy

Use any container registry manipulation tool (e.g , [crane][crane], [ORAS][oras], [regclient][regclient]) to copy the images to your destination registry.
For example,

```bash
oras cp ghcr.io/aquasecurity/trivy-db:2 registry.my-company.example/trivy-db-mirror:2
```

!!! note
    You will need to keep the databases updated in order to maintain relevant scanning results over time.

### Configure Trivy

Use the appropriate [asset location flags][custom-locations] to change the repository location:

### Authentication

If the registry requires authentication, you can configure it as described in the [private registry authentication document][private].

### OCI Media Types

When serving, proxying, or manipulating Trivy's assets, note that the media type of the OCI layer is not a standard container image type:

| DB               | Media Type                                               | Reference                                                                  |
|------------------|----------------------------------------------------------|----------------------------------------------------------------------------|
| Vulnerability DB | `application/vnd.aquasec.trivy.db.layer.v1.tar+gzip`     | https://github.com/aquasecurity/trivy-db/pkgs/container/trivy-db           |
| Java Index DB    | `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` | https://github.com/aquasecurity/trivy-java-db/pkgs/container/trivy-java-db |
| Checks Bundle    | `application/vnd.oci.image.manifest.v1+json`             | https://github.com/aquasecurity/trivy-checks/pkgs/container/trivy-checks   |

## VEX Hub

To host VEX Hub in your own infrastructure:

### Make a local copy

Sync [the VEX Hub repository][vexhub] to a location that is accessible to Trivy.

https://docs.github.com/en/repositories/creating-and-managing-repositories/duplicating-a-repository

!!! note
    You will need to keep the repository updated in order to maintain relevant scanning results over time.

### Configure Trivy

Use the appropriate [configuration][custom-vex-repo]) to change the repository location:

### Authentication

If the repository requires authentication, you can configure it as described [here][vex-repo-auth].

[oras]: https://oras.land
[crane]: https://docs.github.com/en/repositories/creating-and-managing-repositories/duplicating-a-repository
[regclient]: https://docs.github.com/en/repositories/creating-and-managing-repositories/duplicating-a-repository

[assets]: ./index.md
[custom-locations]: ../configuration/scan-assets.md#custom-locations
[private]: ../advanced/private-registries/index.md
[vexhub]: https://github.com/aquasecurity/vexhub
[custom-vex-repo]: ../supply-chain/vex/repo.md#custom-repositories
[vex-repo-auth]: ../supply-chain/vex/repo.md#authentication