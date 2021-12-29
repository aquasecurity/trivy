# Podman

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Scan your image in Podman (>=2.0) running locally. The remote Podman is not supported.
Before performing Trivy commands, you must enable the podman.sock systemd service on your machine.
For more details, see [here][sock].


```bash
$ systemctl --user enable --now podman.socket
```

Then, you can scan your image in Podman.

```bash
$ cat Dockerfile
FROM alpine:3.12
RUN apk add --no-cache bash
$ podman build -t test .
$ podman images
REPOSITORY                TAG     IMAGE ID      CREATED      SIZE
localhost/test            latest  efc372d4e0de  About a minute ago  7.94 MB
$ trivy image test
```

[sock]: https://github.com/containers/podman/blob/master/docs/tutorials/remote_client.md#enable-the-podman-service-on-the-server-machine
