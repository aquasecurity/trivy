# Spring4Shell module

This module provides a more in-depth investigation of Spring4Shell detection.

## Set up

```
$ tinygo build -o spring4shell.wasm -scheduler=none -target=wasi --no-debug spring4shell.go 
$ mkdir -p ~/.trivy/modules
$ cp spring4shell.wasm ~/.trivy/modules
```

It is also available in [GHCR][trivy-module-spring4shell].
You can install it via `trivy module install`.

```bash
$ trivy module install ghcr.io/aquasecurity/trivy-module-spring4shell
2022-06-13T15:32:21.972+0300    INFO    Installing the module from ghcr.io/aquasecurity/trivy-module-spring4shell...
```

## Run Trivy

```
$ trivy image spring-core-rce-jdk8:latest
2022-05-29T22:35:04.873+0300    INFO    Loading spring4shell.wasm...
2022-05-29T22:35:05.348+0300    INFO    Registering WASM module: spring4shell@v1
2022-05-29T22:35:07.124+0300    INFO    Module spring4shell: analyzing /app/tomcat/RELEASE-NOTES...
2022-05-29T22:35:07.139+0300    INFO    Module spring4shell: analyzing /app/jdk9/release...
2022-05-29T22:37:04.636+0300    INFO    Module spring4shell: analyzing /app/jdk9/release...
...
2022-05-29T22:37:08.917+0300    INFO    Module spring4shell: Java Version: 8, Tomcat Version: 8.5.77
2022-05-29T22:37:08.917+0300    INFO    Module spring4shell: change CVE-2022-22965 severity from CRITICAL to LOW
```

In the above example, the Java version is 8 which is not affected by CVE-2022-22965, so this module changes the severity from CRITICAL to LOW.

## Note
This module is also used for testing in Trivy.

[trivy-module-spring4shell]: https://github.com/orgs/aquasecurity/packages/container/package/trivy-module-spring4shell