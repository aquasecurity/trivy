# Trivy Scanner

Trivy vulnerability scanner standalone installation.

## TL;DR;

```
$ helm install trivy . --namespace trivy --create-namespace
```

## Introduction

This chart bootstraps a Trivy deployment on a [Kubernetes](http://kubernetes.io) cluster using the
[Helm](https://helm.sh) package manager.

## Prerequisites

- Kubernetes 1.12+
- Helm 3+

## Installing from the the Aqua Chart Repository

```
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo update
helm search repo trivy
helm install my-trivy aquasecurity/trivy
```

## Installing the Chart

To install the chart with the release name `my-release`:

```
$ helm install my-release .
```

The command deploys Trivy on the Kubernetes cluster in the default configuration. The [Parameters](#parameters)
section lists the parameters that can be configured during installation.

> **Tip**: List all releases using `helm list`.

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Parameters

The following table lists the configurable parameters of the Trivy chart and their default values.

|                 Parameter             |                                Description                              |    Default     |
|---------------------------------------|-------------------------------------------------------------------------|----------------|
| `image.registry`                      | Image registry                                                          | `docker.io`    |
| `image.repository`                    | Image name                                                              | `aquasec/trivy` |
| `image.tag`                           | Image tag                                                               | `{TAG_NAME}`   |
| `image.pullPolicy`                    | Image pull policy                                                       | `IfNotPresent` |
| `image.pullSecret`                    | The name of an imagePullSecret used to pull trivy image from e.g. Docker Hub or a private registry  | |
| `replicaCount`                        | Number of Trivy Pods to run                                   | `1`            |
| `trivy.debugMode`             | The flag to enable or disable Trivy debug mode                          | `false` |
| `trivy.gitHubToken`           | The GitHub access token to download Trivy DB. More info: https://github.com/aquasecurity/trivy#github-rate-limiting                          |      |
| `trivy.skipUpdate`            | The flag to enable or disable Trivy DB downloads from GitHub            | `false`        |
| `trivy.cache.redis.enabled`           | Enable Redis as caching backend                                         | `false` |
| `trivy.cache.redis.url`               | Specify redis connection url, e.g. redis://redis.redis.svc:6379         | `` |
| `service.type`                        | Kubernetes service type                                                 | `ClusterIP` |
| `service.port`                        | Kubernetes service port                                                 | `4954`      |
| `httpProxy`                           | The URL of the HTTP proxy server                                        |     |
| `httpsProxy`                          | The URL of the HTTPS proxy server                                       |     |
| `noProxy`                             | The URLs that the proxy settings do not apply to                        |     |
| `nodeSelector`                        | Node labels for pod assignment                                              |     |
| `affinity`                        | Affinity settings for pod assignment                                              |     |
| `tolerations`                        | Tolerations for pod assignment                                              |     |

The above parameters map to the env variables defined in [trivy](https://github.com/aquasecurity/trivy#configuration).

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

```
$ helm install my-release . \
       --namespace my-namespace \
       --set "service.port=9090" \
       --set "trivy.vulnType=os\,library"
```

## Storage

This chart uses a PersistentVolumeClaim to reduce the number of database downloads between POD restarts or updates. The storageclass should have the reclaim policy  `Retain`.

## Caching

You can specify a Redis server as cache backend. This Redis server has to be already present. You can use the [bitname chart](https://bitnami.com/stack/redis/helm).
More Information about the caching backends can be found [here](https://github.com/aquasecurity/trivy#specify-cache-backend).
