# OCI

An image directory compliant with "Open Container Image Layout Specification".

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
