# WoredPress module

This module provides a more in-depth investigation of Wordpress detection.

## Set up

```
$ tinygo build -o wordpress.wasm -scheduler=none -target=wasi --no-debug wordpress.go 
$ mkdir -p ~/.trivy/modules
$ cp wordpress.wasm ~/.trivy/modules
```

It is also available in [GHCR][trivy-module-wordpress].
You can install it via `trivy module install`.

```bash
$ trivy module install ghcr.io/aquasecurity/trivy-module-wordpress
2022-06-13T15:32:21.972+0300    INFO    Installing the module from ghcr.io/aquasecurity/trivy-module-wordpress...
```

## Run Trivy

```
$ trivy image wordpress:5.7.1
2022-05-29T22:35:04.873+0300    INFO    Loading wordpress.wasm...
2022-05-29T22:35:05.348+0300    INFO    Registering WASM module: wordpress@v1
```

In the above example, CVE-2020-36326 and CVE-2018-19296 will be detected if the WordPress version is vulnerable.

[trivy-module-wordpress]: https://github.com/orgs/aquasecurity/packages/container/package/trivy-module-wordpress