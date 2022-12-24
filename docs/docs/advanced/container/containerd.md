# containerd

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Scan your image in [containerd][containerd] running locally.

```bash
$ nerdctl images
REPOSITORY        TAG       IMAGE ID        CREATED         PLATFORM       SIZE         BLOB SIZE
aquasec/nginx    latest    2bcabc23b454    3 hours ago     linux/amd64    149.1 MiB    54.1 MiB
$ trivy image aquasec/nginx
```

If your containerd socket is not the default path (`//run/containerd/containerd.sock`), you can override it via `CONTAINERD_ADDRESS`.

```bash
$ export CONTAINERD_ADDRESS=/run/k3s/containerd/containerd.sock
$ trivy image aquasec/nginx
```

If your scan targets are images in a namespace other than containerd's default namespace (`default`), you can override it via `CONTAINERD_NAMESPACE`.

```bash
$ export CONTAINERD_NAMESPACE=k8s.io
$ trivy image aquasec/nginx
```

[containerd]: https://containerd.io/
