# Embed in Dockerfile

You can scan your image as part of the image build process by embedding Trivy in the Dockerfile. 
When scanning the container contents, use the [rootfs](../../target/rootfs.md) target.

Examples:

Using the [Trivy install script](../../../getting-started/installation.md#install-script-official):

```Dockerfile
FROM ...
// your build steps

RUN apk add curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && trivy rootfs --exit-code 1 --no-progress /
```

Using the [Trivy official image](../../../getting-started/installation.md#container-image-official) to avoid insecure `curl | sh`:

```Dockerfile
FROM ...
// your build steps

COPY --from=aquasec/trivy:latest /usr/local/bin/trivy /usr/local/bin/trivy
RUN trivy rootfs --exit-code 1 --no-progress /
```

Using multi-stage build to separate scanning from the build artifact:

```Dockerfile
FROM ... as build
// your build steps

FROM build as vulnscan
COPY --from=aquasec/trivy:latest /usr/local/bin/trivy /usr/local/bin/trivy
RUN trivy rootfs --exit-code 1 --no-progress /

FROM build
```

