# OCI Image Layout

An image directory compliant with [Open Container Image Layout Specification](https://github.com/opencontainers/image-spec/blob/master/spec.md).

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
