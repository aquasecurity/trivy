<!--- app-name: MySQL -->

# MySQL packaged by Bitnami

MySQL is a fast, reliable, scalable, and easy to use open source relational database system. Designed to handle mission-critical, heavy-load production applications.

[Overview of MySQL](http://www.mysql.com)

Trademarks: This software listing is packaged by Bitnami. The respective trademarks mentioned in the offering are owned by the respective companies, and use of them does not imply any affiliation or endorsement.
                           
## TL;DR

```bash
$ helm repo add bitnami https://charts.bitnami.com/bitnami
$ helm install my-release bitnami/mysql
```

## Introduction

This chart bootstraps a [MySQL](https://github.com/bitnami/bitnami-docker-mysql) replication cluster deployment on a [Kubernetes](https://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

Bitnami charts can be used with [Kubeapps](https://kubeapps.com/) for deployment and management of Helm Charts in clusters. This Helm chart has been tested on top of [Bitnami Kubernetes Production Runtime](https://kubeprod.io/) (BKPR). Deploy BKPR to get automated TLS certificates, logging and monitoring for your applications.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- PV provisioner support in the underlying infrastructure

## Installing the Chart

To install the chart with the release name `my-release`:

```bash
$ helm repo add bitnami https://charts.bitnami.com/bitnami
$ helm install my-release bitnami/mysql
```

These commands deploy MySQL on the Kubernetes cluster in the default configuration. The [Parameters](#parameters) section lists the parameters that can be configured during installation.

> **Tip**: List all releases using `helm list`

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```bash
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Parameters

### Global parameters

| Name                      | Description                                     | Value |
| ------------------------- | ----------------------------------------------- | ----- |
| `global.imageRegistry`    | Global Docker image registry                    | `""`  |
| `global.imagePullSecrets` | Global Docker registry secret names as an array | `[]`  |
| `global.storageClass`     | Global StorageClass for Persistent Volume(s)    | `""`  |


### Common parameters

| Name                     | Description                                                                                               | Value           |
| ------------------------ | --------------------------------------------------------------------------------------------------------- | --------------- |
| `nameOverride`           | String to partially override common.names.fullname template (will maintain the release name)              | `""`            |
| `fullnameOverride`       | String to fully override common.names.fullname template                                                   | `""`            |
| `clusterDomain`          | Cluster domain                                                                                            | `cluster.local` |
| `commonAnnotations`      | Common annotations to add to all MySQL resources (sub-charts are not considered). Evaluated as a template | `{}`            |
| `commonLabels`           | Common labels to add to all MySQL resources (sub-charts are not considered). Evaluated as a template      | `{}`            |
| `extraDeploy`            | Array with extra yaml to deploy with the chart. Evaluated as a template                                   | `[]`            |
| `schedulerName`          | Use an alternate scheduler, e.g. "stork".                                                                 | `""`            |
| `diagnosticMode.enabled` | Enable diagnostic mode (all probes will be disabled and the command will be overridden)                   | `false`         |
| `diagnosticMode.command` | Command to override all containers in the deployment                                                      | `["sleep"]`     |
| `diagnosticMode.args`    | Args to override all containers in the deployment                                                         | `["infinity"]`  |


### MySQL common parameters

| Name                       | Description                                                                                                                                                                         | Value                 |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `image.registry`           | MySQL image registry                                                                                                                                                                | `docker.io`           |
| `image.repository`         | MySQL image repository                                                                                                                                                              | `bitnami/mysql`       |
| `image.tag`                | MySQL image tag (immutable tags are recommended)                                                                                                                                    | `8.0.28-debian-10-r0` |
| `image.pullPolicy`         | MySQL image pull policy                                                                                                                                                             | `IfNotPresent`        |
| `image.pullSecrets`        | Specify docker-registry secret names as an array                                                                                                                                    | `[]`                  |
| `image.debug`              | Specify if debug logs should be enabled                                                                                                                                             | `false`               |
| `architecture`             | MySQL architecture (`standalone` or `replication`)                                                                                                                                  | `standalone`          |
| `auth.rootPassword`        | Password for the `root` user. Ignored if existing secret is provided                                                                                                                | `""`                  |
| `auth.database`            | Name for a custom database to create                                                                                                                                                | `my_database`         |
| `auth.username`            | Name for a custom user to create                                                                                                                                                    | `""`                  |
| `auth.password`            | Password for the new user. Ignored if existing secret is provided                                                                                                                   | `""`                  |
| `auth.replicationUser`     | MySQL replication user                                                                                                                                                              | `replicator`          |
| `auth.replicationPassword` | MySQL replication user password. Ignored if existing secret is provided                                                                                                             | `""`                  |
| `auth.existingSecret`      | Use existing secret for password details. The secret has to contain the keys `mysql-root-password`, `mysql-replication-password` and `mysql-password`                               | `""`                  |
| `auth.forcePassword`       | Force users to specify required passwords                                                                                                                                           | `false`               |
| `auth.usePasswordFiles`    | Mount credentials as files instead of using an environment variable                                                                                                                 | `false`               |
| `auth.customPasswordFiles` | Use custom password files when `auth.usePasswordFiles` is set to `true`. Define path for keys `root` and `user`, also define `replicator` if `architecture` is set to `replication` | `{}`                  |
| `initdbScripts`            | Dictionary of initdb scripts                                                                                                                                                        | `{}`                  |
| `initdbScriptsConfigMap`   | ConfigMap with the initdb scripts (Note: Overrides `initdbScripts`)                                                                                                                 | `""`                  |


### MySQL Primary parameters

| Name                                         | Description                                                                                                     | Value               |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------- |
| `primary.command`                            | Override default container command on MySQL Primary container(s) (useful when using custom images)              | `[]`                |
| `primary.args`                               | Override default container args on MySQL Primary container(s) (useful when using custom images)                 | `[]`                |
| `primary.hostAliases`                        | Deployment pod host aliases                                                                                     | `[]`                |
| `primary.configuration`                      | Configure MySQL Primary with a custom my.cnf file                                                               | `""`                |
| `primary.existingConfigmap`                  | Name of existing ConfigMap with MySQL Primary configuration.                                                    | `""`                |
| `primary.updateStrategy`                     | Update strategy type for the MySQL primary statefulset                                                          | `RollingUpdate`     |
| `primary.rollingUpdatePartition`             | Partition update strategy for MySQL Primary statefulset                                                         | `""`                |
| `primary.podAnnotations`                     | Additional pod annotations for MySQL primary pods                                                               | `{}`                |
| `primary.podAffinityPreset`                  | MySQL primary pod affinity preset. Ignored if `primary.affinity` is set. Allowed values: `soft` or `hard`       | `""`                |
| `primary.podAntiAffinityPreset`              | MySQL primary pod anti-affinity preset. Ignored if `primary.affinity` is set. Allowed values: `soft` or `hard`  | `soft`              |
| `primary.nodeAffinityPreset.type`            | MySQL primary node affinity preset type. Ignored if `primary.affinity` is set. Allowed values: `soft` or `hard` | `""`                |
| `primary.nodeAffinityPreset.key`             | MySQL primary node label key to match Ignored if `primary.affinity` is set.                                     | `""`                |
| `primary.nodeAffinityPreset.values`          | MySQL primary node label values to match. Ignored if `primary.affinity` is set.                                 | `[]`                |
| `primary.affinity`                           | Affinity for MySQL primary pods assignment                                                                      | `{}`                |
| `primary.nodeSelector`                       | Node labels for MySQL primary pods assignment                                                                   | `{}`                |
| `primary.tolerations`                        | Tolerations for MySQL primary pods assignment                                                                   | `[]`                |
| `primary.podSecurityContext.enabled`         | Enable security context for MySQL primary pods                                                                  | `true`              |
| `primary.podSecurityContext.fsGroup`         | Group ID for the mounted volumes' filesystem                                                                    | `1001`              |
| `primary.containerSecurityContext.enabled`   | MySQL primary container securityContext                                                                         | `true`              |
| `primary.containerSecurityContext.runAsUser` | User ID for the MySQL primary container                                                                         | `1001`              |
| `primary.resources.limits`                   | The resources limits for MySQL primary containers                                                               | `{}`                |
| `primary.resources.requests`                 | The requested resources for MySQL primary containers                                                            | `{}`                |
| `primary.livenessProbe.enabled`              | Enable livenessProbe                                                                                            | `true`              |
| `primary.livenessProbe.initialDelaySeconds`  | Initial delay seconds for livenessProbe                                                                         | `5`                 |
| `primary.livenessProbe.periodSeconds`        | Period seconds for livenessProbe                                                                                | `10`                |
| `primary.livenessProbe.timeoutSeconds`       | Timeout seconds for livenessProbe                                                                               | `1`                 |
| `primary.livenessProbe.failureThreshold`     | Failure threshold for livenessProbe                                                                             | `3`                 |
| `primary.livenessProbe.successThreshold`     | Success threshold for livenessProbe                                                                             | `1`                 |
| `primary.readinessProbe.enabled`             | Enable readinessProbe                                                                                           | `true`              |
| `primary.readinessProbe.initialDelaySeconds` | Initial delay seconds for readinessProbe                                                                        | `5`                 |
| `primary.readinessProbe.periodSeconds`       | Period seconds for readinessProbe                                                                               | `10`                |
| `primary.readinessProbe.timeoutSeconds`      | Timeout seconds for readinessProbe                                                                              | `1`                 |
| `primary.readinessProbe.failureThreshold`    | Failure threshold for readinessProbe                                                                            | `3`                 |
| `primary.readinessProbe.successThreshold`    | Success threshold for readinessProbe                                                                            | `1`                 |
| `primary.startupProbe.enabled`               | Enable startupProbe                                                                                             | `true`              |
| `primary.startupProbe.initialDelaySeconds`   | Initial delay seconds for startupProbe                                                                          | `15`                |
| `primary.startupProbe.periodSeconds`         | Period seconds for startupProbe                                                                                 | `10`                |
| `primary.startupProbe.timeoutSeconds`        | Timeout seconds for startupProbe                                                                                | `1`                 |
| `primary.startupProbe.failureThreshold`      | Failure threshold for startupProbe                                                                              | `10`                |
| `primary.startupProbe.successThreshold`      | Success threshold for startupProbe                                                                              | `1`                 |
| `primary.customLivenessProbe`                | Override default liveness probe for MySQL primary containers                                                    | `{}`                |
| `primary.customReadinessProbe`               | Override default readiness probe for MySQL primary containers                                                   | `{}`                |
| `primary.customStartupProbe`                 | Override default startup probe for MySQL primary containers                                                     | `{}`                |
| `primary.extraFlags`                         | MySQL primary additional command line flags                                                                     | `""`                |
| `primary.extraEnvVars`                       | Extra environment variables to be set on MySQL primary containers                                               | `[]`                |
| `primary.extraEnvVarsCM`                     | Name of existing ConfigMap containing extra env vars for MySQL primary containers                               | `""`                |
| `primary.extraEnvVarsSecret`                 | Name of existing Secret containing extra env vars for MySQL primary containers                                  | `""`                |
| `primary.persistence.enabled`                | Enable persistence on MySQL primary replicas using a `PersistentVolumeClaim`. If false, use emptyDir            | `true`              |
| `primary.persistence.existingClaim`          | Name of an existing `PersistentVolumeClaim` for MySQL primary replicas                                          | `""`                |
| `primary.persistence.storageClass`           | MySQL primary persistent volume storage Class                                                                   | `""`                |
| `primary.persistence.annotations`            | MySQL primary persistent volume claim annotations                                                               | `{}`                |
| `primary.persistence.accessModes`            | MySQL primary persistent volume access Modes                                                                    | `["ReadWriteOnce"]` |
| `primary.persistence.size`                   | MySQL primary persistent volume size                                                                            | `8Gi`               |
| `primary.persistence.selector`               | Selector to match an existing Persistent Volume                                                                 | `{}`                |
| `primary.extraVolumes`                       | Optionally specify extra list of additional volumes to the MySQL Primary pod(s)                                 | `[]`                |
| `primary.extraVolumeMounts`                  | Optionally specify extra list of additional volumeMounts for the MySQL Primary container(s)                     | `[]`                |
| `primary.initContainers`                     | Add additional init containers for the MySQL Primary pod(s)                                                     | `[]`                |
| `primary.sidecars`                           | Add additional sidecar containers for the MySQL Primary pod(s)                                                  | `[]`                |
| `primary.service.type`                       | MySQL Primary K8s service type                                                                                  | `ClusterIP`         |
| `primary.service.port`                       | MySQL Primary K8s service port                                                                                  | `3306`              |
| `primary.service.nodePort`                   | MySQL Primary K8s service node port                                                                             | `""`                |
| `primary.service.clusterIP`                  | MySQL Primary K8s service clusterIP IP                                                                          | `""`                |
| `primary.service.loadBalancerIP`             | MySQL Primary loadBalancerIP if service type is `LoadBalancer`                                                  | `""`                |
| `primary.service.externalTrafficPolicy`      | Enable client source IP preservation                                                                            | `Cluster`           |
| `primary.service.loadBalancerSourceRanges`   | Addresses that are allowed when MySQL Primary service is LoadBalancer                                           | `[]`                |
| `primary.service.annotations`                | Provide any additional annotations which may be required                                                        | `{}`                |
| `primary.pdb.enabled`                        | Enable/disable a Pod Disruption Budget creation for MySQL primary pods                                          | `false`             |
| `primary.pdb.minAvailable`                   | Minimum number/percentage of MySQL primary pods that should remain scheduled                                    | `1`                 |
| `primary.pdb.maxUnavailable`                 | Maximum number/percentage of MySQL primary pods that may be made unavailable                                    | `""`                |
| `primary.podLabels`                          | MySQL Primary pod label. If labels are same as commonLabels , this will take precedence                         | `{}`                |


### MySQL Secondary parameters

| Name                                           | Description                                                                                                         | Value               |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------- |
| `secondary.replicaCount`                       | Number of MySQL secondary replicas                                                                                  | `1`                 |
| `secondary.hostAliases`                        | Deployment pod host aliases                                                                                         | `[]`                |
| `secondary.command`                            | Override default container command on MySQL Secondary container(s) (useful when using custom images)                | `[]`                |
| `secondary.args`                               | Override default container args on MySQL Secondary container(s) (useful when using custom images)                   | `[]`                |
| `secondary.configuration`                      | Configure MySQL Secondary with a custom my.cnf file                                                                 | `""`                |
| `secondary.existingConfigmap`                  | Name of existing ConfigMap with MySQL Secondary configuration.                                                      | `""`                |
| `secondary.updateStrategy`                     | Update strategy type for the MySQL secondary statefulset                                                            | `RollingUpdate`     |
| `secondary.rollingUpdatePartition`             | Partition update strategy for MySQL Secondary statefulset                                                           | `""`                |
| `secondary.podAnnotations`                     | Additional pod annotations for MySQL secondary pods                                                                 | `{}`                |
| `secondary.podAffinityPreset`                  | MySQL secondary pod affinity preset. Ignored if `secondary.affinity` is set. Allowed values: `soft` or `hard`       | `""`                |
| `secondary.podAntiAffinityPreset`              | MySQL secondary pod anti-affinity preset. Ignored if `secondary.affinity` is set. Allowed values: `soft` or `hard`  | `soft`              |
| `secondary.nodeAffinityPreset.type`            | MySQL secondary node affinity preset type. Ignored if `secondary.affinity` is set. Allowed values: `soft` or `hard` | `""`                |
| `secondary.nodeAffinityPreset.key`             | MySQL secondary node label key to match Ignored if `secondary.affinity` is set.                                     | `""`                |
| `secondary.nodeAffinityPreset.values`          | MySQL secondary node label values to match. Ignored if `secondary.affinity` is set.                                 | `[]`                |
| `secondary.affinity`                           | Affinity for MySQL secondary pods assignment                                                                        | `{}`                |
| `secondary.nodeSelector`                       | Node labels for MySQL secondary pods assignment                                                                     | `{}`                |
| `secondary.tolerations`                        | Tolerations for MySQL secondary pods assignment                                                                     | `[]`                |
| `secondary.podSecurityContext.enabled`         | Enable security context for MySQL secondary pods                                                                    | `true`              |
| `secondary.podSecurityContext.fsGroup`         | Group ID for the mounted volumes' filesystem                                                                        | `1001`              |
| `secondary.containerSecurityContext.enabled`   | MySQL secondary container securityContext                                                                           | `true`              |
| `secondary.containerSecurityContext.runAsUser` | User ID for the MySQL secondary container                                                                           | `1001`              |
| `secondary.resources.limits`                   | The resources limits for MySQL secondary containers                                                                 | `{}`                |
| `secondary.resources.requests`                 | The requested resources for MySQL secondary containers                                                              | `{}`                |
| `secondary.livenessProbe.enabled`              | Enable livenessProbe                                                                                                | `true`              |
| `secondary.livenessProbe.initialDelaySeconds`  | Initial delay seconds for livenessProbe                                                                             | `5`                 |
| `secondary.livenessProbe.periodSeconds`        | Period seconds for livenessProbe                                                                                    | `10`                |
| `secondary.livenessProbe.timeoutSeconds`       | Timeout seconds for livenessProbe                                                                                   | `1`                 |
| `secondary.livenessProbe.failureThreshold`     | Failure threshold for livenessProbe                                                                                 | `3`                 |
| `secondary.livenessProbe.successThreshold`     | Success threshold for livenessProbe                                                                                 | `1`                 |
| `secondary.readinessProbe.enabled`             | Enable readinessProbe                                                                                               | `true`              |
| `secondary.readinessProbe.initialDelaySeconds` | Initial delay seconds for readinessProbe                                                                            | `5`                 |
| `secondary.readinessProbe.periodSeconds`       | Period seconds for readinessProbe                                                                                   | `10`                |
| `secondary.readinessProbe.timeoutSeconds`      | Timeout seconds for readinessProbe                                                                                  | `1`                 |
| `secondary.readinessProbe.failureThreshold`    | Failure threshold for readinessProbe                                                                                | `3`                 |
| `secondary.readinessProbe.successThreshold`    | Success threshold for readinessProbe                                                                                | `1`                 |
| `secondary.startupProbe.enabled`               | Enable startupProbe                                                                                                 | `true`              |
| `secondary.startupProbe.initialDelaySeconds`   | Initial delay seconds for startupProbe                                                                              | `15`                |
| `secondary.startupProbe.periodSeconds`         | Period seconds for startupProbe                                                                                     | `10`                |
| `secondary.startupProbe.timeoutSeconds`        | Timeout seconds for startupProbe                                                                                    | `1`                 |
| `secondary.startupProbe.failureThreshold`      | Failure threshold for startupProbe                                                                                  | `15`                |
| `secondary.startupProbe.successThreshold`      | Success threshold for startupProbe                                                                                  | `1`                 |
| `secondary.customLivenessProbe`                | Override default liveness probe for MySQL secondary containers                                                      | `{}`                |
| `secondary.customReadinessProbe`               | Override default readiness probe for MySQL secondary containers                                                     | `{}`                |
| `secondary.customStartupProbe`                 | Override default startup probe for MySQL secondary containers                                                       | `{}`                |
| `secondary.extraFlags`                         | MySQL secondary additional command line flags                                                                       | `""`                |
| `secondary.extraEnvVars`                       | An array to add extra environment variables on MySQL secondary containers                                           | `[]`                |
| `secondary.extraEnvVarsCM`                     | Name of existing ConfigMap containing extra env vars for MySQL secondary containers                                 | `""`                |
| `secondary.extraEnvVarsSecret`                 | Name of existing Secret containing extra env vars for MySQL secondary containers                                    | `""`                |
| `secondary.persistence.enabled`                | Enable persistence on MySQL secondary replicas using a `PersistentVolumeClaim`                                      | `true`              |
| `secondary.persistence.storageClass`           | MySQL secondary persistent volume storage Class                                                                     | `""`                |
| `secondary.persistence.annotations`            | MySQL secondary persistent volume claim annotations                                                                 | `{}`                |
| `secondary.persistence.accessModes`            | MySQL secondary persistent volume access Modes                                                                      | `["ReadWriteOnce"]` |
| `secondary.persistence.size`                   | MySQL secondary persistent volume size                                                                              | `8Gi`               |
| `secondary.persistence.selector`               | Selector to match an existing Persistent Volume                                                                     | `{}`                |
| `secondary.extraVolumes`                       | Optionally specify extra list of additional volumes to the MySQL secondary pod(s)                                   | `[]`                |
| `secondary.extraVolumeMounts`                  | Optionally specify extra list of additional volumeMounts for the MySQL secondary container(s)                       | `[]`                |
| `secondary.initContainers`                     | Add additional init containers for the MySQL secondary pod(s)                                                       | `[]`                |
| `secondary.sidecars`                           | Add additional sidecar containers for the MySQL secondary pod(s)                                                    | `[]`                |
| `secondary.service.type`                       | MySQL secondary Kubernetes service type                                                                             | `ClusterIP`         |
| `secondary.service.port`                       | MySQL secondary Kubernetes service port                                                                             | `3306`              |
| `secondary.service.nodePort`                   | MySQL secondary Kubernetes service node port                                                                        | `""`                |
| `secondary.service.clusterIP`                  | MySQL secondary Kubernetes service clusterIP IP                                                                     | `""`                |
| `secondary.service.loadBalancerIP`             | MySQL secondary loadBalancerIP if service type is `LoadBalancer`                                                    | `""`                |
| `secondary.service.externalTrafficPolicy`      | Enable client source IP preservation                                                                                | `Cluster`           |
| `secondary.service.loadBalancerSourceRanges`   | Addresses that are allowed when MySQL secondary service is LoadBalancer                                             | `[]`                |
| `secondary.service.annotations`                | Provide any additional annotations which may be required                                                            | `{}`                |
| `secondary.pdb.enabled`                        | Enable/disable a Pod Disruption Budget creation for MySQL secondary pods                                            | `false`             |
| `secondary.pdb.minAvailable`                   | Minimum number/percentage of MySQL secondary pods that should remain scheduled                                      | `1`                 |
| `secondary.pdb.maxUnavailable`                 | Maximum number/percentage of MySQL secondary pods that may be made unavailable                                      | `""`                |
| `secondary.podLabels`                          | Additional pod labels for MySQL secondary pods                                                                      | `{}`                |


### RBAC parameters

| Name                         | Description                                            | Value   |
| ---------------------------- | ------------------------------------------------------ | ------- |
| `serviceAccount.create`      | Enable the creation of a ServiceAccount for MySQL pods | `true`  |
| `serviceAccount.name`        | Name of the created ServiceAccount                     | `""`    |
| `serviceAccount.annotations` | Annotations for MySQL Service Account                  | `{}`    |
| `rbac.create`                | Whether to create & use RBAC resources or not          | `false` |


### Network Policy

| Name                                       | Description                                                                                                     | Value   |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------- |
| `networkPolicy.enabled`                    | Enable creation of NetworkPolicy resources                                                                      | `false` |
| `networkPolicy.allowExternal`              | The Policy model to apply.                                                                                      | `true`  |
| `networkPolicy.explicitNamespacesSelector` | A Kubernetes LabelSelector to explicitly select namespaces from which ingress traffic could be allowed to MySQL | `{}`    |


### Volume Permissions parameters

| Name                                  | Description                                                                                                          | Value                   |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `volumePermissions.enabled`           | Enable init container that changes the owner and group of the persistent volume(s) mountpoint to `runAsUser:fsGroup` | `false`                 |
| `volumePermissions.image.registry`    | Init container volume-permissions image registry                                                                     | `docker.io`             |
| `volumePermissions.image.repository`  | Init container volume-permissions image repository                                                                   | `bitnami/bitnami-shell` |
| `volumePermissions.image.tag`         | Init container volume-permissions image tag (immutable tags are recommended)                                         | `10-debian-10-r312`     |
| `volumePermissions.image.pullPolicy`  | Init container volume-permissions image pull policy                                                                  | `IfNotPresent`          |
| `volumePermissions.image.pullSecrets` | Specify docker-registry secret names as an array                                                                     | `[]`                    |
| `volumePermissions.resources`         | Init container volume-permissions resources                                                                          | `{}`                    |


### Metrics parameters

| Name                                         | Description                                                                                                           | Value                     |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `metrics.enabled`                            | Start a side-car prometheus exporter                                                                                  | `false`                   |
| `metrics.image.registry`                     | Exporter image registry                                                                                               | `docker.io`               |
| `metrics.image.repository`                   | Exporter image repository                                                                                             | `bitnami/mysqld-exporter` |
| `metrics.image.tag`                          | Exporter image tag (immutable tags are recommended)                                                                   | `0.13.0-debian-10-r216`   |
| `metrics.image.pullPolicy`                   | Exporter image pull policy                                                                                            | `IfNotPresent`            |
| `metrics.image.pullSecrets`                  | Specify docker-registry secret names as an array                                                                      | `[]`                      |
| `metrics.service.type`                       | Kubernetes service type for MySQL Prometheus Exporter                                                                 | `ClusterIP`               |
| `metrics.service.port`                       | MySQL Prometheus Exporter service port                                                                                | `9104`                    |
| `metrics.service.annotations`                | Prometheus exporter service annotations                                                                               | `{}`                      |
| `metrics.extraArgs.primary`                  | Extra args to be passed to mysqld_exporter on Primary pods                                                            | `[]`                      |
| `metrics.extraArgs.secondary`                | Extra args to be passed to mysqld_exporter on Secondary pods                                                          | `[]`                      |
| `metrics.resources.limits`                   | The resources limits for MySQL prometheus exporter containers                                                         | `{}`                      |
| `metrics.resources.requests`                 | The requested resources for MySQL prometheus exporter containers                                                      | `{}`                      |
| `metrics.livenessProbe.enabled`              | Enable livenessProbe                                                                                                  | `true`                    |
| `metrics.livenessProbe.initialDelaySeconds`  | Initial delay seconds for livenessProbe                                                                               | `120`                     |
| `metrics.livenessProbe.periodSeconds`        | Period seconds for livenessProbe                                                                                      | `10`                      |
| `metrics.livenessProbe.timeoutSeconds`       | Timeout seconds for livenessProbe                                                                                     | `1`                       |
| `metrics.livenessProbe.failureThreshold`     | Failure threshold for livenessProbe                                                                                   | `3`                       |
| `metrics.livenessProbe.successThreshold`     | Success threshold for livenessProbe                                                                                   | `1`                       |
| `metrics.readinessProbe.enabled`             | Enable readinessProbe                                                                                                 | `true`                    |
| `metrics.readinessProbe.initialDelaySeconds` | Initial delay seconds for readinessProbe                                                                              | `30`                      |
| `metrics.readinessProbe.periodSeconds`       | Period seconds for readinessProbe                                                                                     | `10`                      |
| `metrics.readinessProbe.timeoutSeconds`      | Timeout seconds for readinessProbe                                                                                    | `1`                       |
| `metrics.readinessProbe.failureThreshold`    | Failure threshold for readinessProbe                                                                                  | `3`                       |
| `metrics.readinessProbe.successThreshold`    | Success threshold for readinessProbe                                                                                  | `1`                       |
| `metrics.serviceMonitor.enabled`             | Create ServiceMonitor Resource for scraping metrics using PrometheusOperator                                          | `false`                   |
| `metrics.serviceMonitor.namespace`           | Specify the namespace in which the serviceMonitor resource will be created                                            | `""`                      |
| `metrics.serviceMonitor.interval`            | Specify the interval at which metrics should be scraped                                                               | `30s`                     |
| `metrics.serviceMonitor.scrapeTimeout`       | Specify the timeout after which the scrape is ended                                                                   | `""`                      |
| `metrics.serviceMonitor.relabellings`        | Specify Metric Relabellings to add to the scrape endpoint                                                             | `[]`                      |
| `metrics.serviceMonitor.honorLabels`         | Specify honorLabels parameter to add the scrape endpoint                                                              | `false`                   |
| `metrics.serviceMonitor.additionalLabels`    | Used to pass Labels that are used by the Prometheus installed in your cluster to select Service Monitors to work with | `{}`                      |


The above parameters map to the env variables defined in [bitnami/mysql](https://github.com/bitnami/bitnami-docker-mysql). For more information please refer to the [bitnami/mysql](https://github.com/bitnami/bitnami-docker-mysql) image documentation.

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`. For example,

```bash
$ helm install my-release \
  --set auth.rootPassword=secretpassword,auth.database=app_database \
    bitnami/mysql
```

The above command sets the MySQL `root` account password to `secretpassword`. Additionally it creates a database named `app_database`.

> NOTE: Once this chart is deployed, it is not possible to change the application's access credentials, such as usernames or passwords, using Helm. To change these application credentials after deployment, delete any persistent volumes (PVs) used by the chart and re-deploy it, or use the application's built-in administrative tools if available.

Alternatively, a YAML file that specifies the values for the parameters can be provided while installing the chart. For example,

```bash
$ helm install my-release -f values.yaml bitnami/mysql
```

> **Tip**: You can use the default [values.yaml](values.yaml)

## Configuration and installation details

### [Rolling VS Immutable tags](https://docs.bitnami.com/containers/how-to/understand-rolling-tags-containers/)

It is strongly recommended to use immutable tags in a production environment. This ensures your deployment does not change automatically if the same tag is updated with a different image.

Bitnami will release a new chart updating its containers if a new version of the main container, significant changes, or critical vulnerabilities exist.

### Use a different MySQL version

To modify the application version used in this chart, specify a different version of the image using the `image.tag` parameter and/or a different repository using the `image.repository` parameter. Refer to the [chart documentation for more information on these parameters and how to use them with images from a private registry](https://docs.bitnami.com/kubernetes/infrastructure/mysql/configuration/change-image-version/).

### Customize a new MySQL instance

The [Bitnami MySQL](https://github.com/bitnami/bitnami-docker-mysql) image allows you to use your custom scripts to initialize a fresh instance. Custom scripts may be specified using the `initdbScripts` parameter. Alternatively, an external ConfigMap may be created with all the initialization scripts and the ConfigMap passed to the chart via the `initdbScriptsConfigMap` parameter. Note that this will override the `initdbScripts` parameter.

The allowed extensions are `.sh`, `.sql` and `.sql.gz`.

These scripts are treated differently depending on their extension. While `.sh` scripts are executed on all the nodes, `.sql` and `.sql.gz` scripts are only executed on the primary nodes. This is because `.sh` scripts support conditional tests to identify the type of node they are running on, while such tests are not supported in `.sql` or `sql.gz` files.

Refer to the [chart documentation for more information and a usage example](http://docs.bitnami.com/kubernetes/infrastructure/mysql/configuration/customize-new-instance/).

### Sidecars and Init Containers

If you have a need for additional containers to run within the same pod as MySQL, you can do so via the `sidecars` config parameter. Simply define your container according to the Kubernetes container spec.

```yaml
sidecars:
  - name: your-image-name
    image: your-image
    imagePullPolicy: Always
    ports:
      - name: portname
       containerPort: 1234
```

Similarly, you can add extra init containers using the `initContainers` parameter.

```yaml
initContainers:
  - name: your-image-name
    image: your-image
    imagePullPolicy: Always
    ports:
      - name: portname
        containerPort: 1234
```

## Persistence

The [Bitnami MySQL](https://github.com/bitnami/bitnami-docker-mysql) image stores the MySQL data and configurations at the `/bitnami/mysql` path of the container.

The chart mounts a [Persistent Volume](https://kubernetes.io/docs/concepts/storage/persistent-volumes/) volume at this location. The volume is created using dynamic volume provisioning by default. An existing PersistentVolumeClaim can also be defined for this purpose.

If you encounter errors when working with persistent volumes, refer to our [troubleshooting guide for persistent volumes](https://docs.bitnami.com/kubernetes/faq/troubleshooting/troubleshooting-persistence-volumes/).

## Network Policy

To enable network policy for MySQL, install [a networking plugin that implements the Kubernetes NetworkPolicy spec](https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy#before-you-begin), and set `networkPolicy.enabled` to `true`.

For Kubernetes v1.5 & v1.6, you must also turn on NetworkPolicy by setting the DefaultDeny namespace annotation. Note: this will enforce policy for _all_ pods in the namespace:

```console
$ kubectl annotate namespace default "net.beta.kubernetes.io/network-policy={\"ingress\":{\"isolation\":\"DefaultDeny\"}}"
```

With NetworkPolicy enabled, traffic will be limited to just port 3306.

For more precise policy, set `networkPolicy.allowExternal=false`. This will only allow pods with the generated client label to connect to MySQL.
This label will be displayed in the output of a successful install.

## Pod affinity

This chart allows you to set your custom affinity using the `XXX.affinity` parameter(s). Find more information about Pod affinity in the [Kubernetes documentation](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#affinity-and-anti-affinity).

As an alternative, you can use the preset configurations for pod affinity, pod anti-affinity, and node affinity available at the [bitnami/common](https://github.com/bitnami/charts/tree/master/bitnami/common#affinities) chart. To do so, set the `XXX.podAffinityPreset`, `XXX.podAntiAffinityPreset`, or `XXX.nodeAffinityPreset` parameters.

## Troubleshooting

Find more information about how to deal with common errors related to Bitnami's Helm charts in [this troubleshooting guide](https://docs.bitnami.com/general/how-to/troubleshoot-helm-chart-issues).

## Upgrading

It's necessary to set the `auth.rootPassword` parameter when upgrading for readiness/liveness probes to work properly. When you install this chart for the first time, some notes will be displayed providing the credentials you must use under the 'Administrator credentials' section. Please note down the password and run the command below to upgrade your chart:

```bash
$ helm upgrade my-release bitnami/mysql --set auth.rootPassword=[ROOT_PASSWORD]
```

| Note: you need to substitute the placeholder _[ROOT_PASSWORD]_ with the value obtained in the installation notes.

### To 8.0.0

- Several parameters were renamed or disappeared in favor of new ones on this major version:
  - The terms *master* and *slave* have been replaced by the terms *primary* and *secondary*. Therefore, parameters prefixed with `master` or `slave` are now prefixed with `primary` or `secondary`, respectively.
  - Credentials parameters are reorganized under the `auth` parameter.
  - `replication.enabled` parameter is deprecated in favor of `architecture` parameter that accepts two values: `standalone` and `replication`.
- Chart labels were adapted to follow the [Helm charts standard labels](https://helm.sh/docs/chart_best_practices/labels/#standard-labels).
- This version also introduces `bitnami/common`, a [library chart](https://helm.sh/docs/topics/library_charts/#helm) as a dependency. More documentation about this new utility could be found [here](https://github.com/bitnami/charts/tree/master/bitnami/common#bitnami-common-library-chart). Please, make sure that you have updated the chart dependencies before executing any upgrade.

Consequences:

- Backwards compatibility is not guaranteed. To upgrade to `8.0.0`, install a new release of the MySQL chart, and migrate the data from your previous release. You have 2 alternatives to do so:
  - Create a backup of the database, and restore it on the new release using tools such as [mysqldump](https://dev.mysql.com/doc/refman/8.0/en/mysqldump.html).
  - Reuse the PVC used to hold the master data on your previous release. To do so, use the `primary.persistence.existingClaim` parameter. The following example assumes that the release name is `mysql`:

```bash
$ helm install mysql bitnami/mysql --set auth.rootPassword=[ROOT_PASSWORD] --set primary.persistence.existingClaim=[EXISTING_PVC]
```

| Note: you need to substitute the placeholder _[EXISTING_PVC]_ with the name of the PVC used on your previous release, and _[ROOT_PASSWORD]_ with the root password used in your previous release.

### To 7.0.0

[On November 13, 2020, Helm v2 support formally ended](https://github.com/helm/charts#status-of-the-project). This major version is the result of the required changes applied to the Helm Chart to be able to incorporate the different features added in Helm v3 and to be consistent with the Helm project itself regarding the Helm v2 EOL.

[Learn more about this change and related upgrade considerations](https://docs.bitnami.com/kubernetes/infrastructure/mysql/administration/upgrade-helm3/).

### To 3.0.0

Backwards compatibility is not guaranteed unless you modify the labels used on the chart's deployments.
Use the workaround below to upgrade from versions previous to 3.0.0. The following example assumes that the release name is mysql:

```console
$ kubectl delete statefulset mysql-master --cascade=false
$ kubectl delete statefulset mysql-slave --cascade=false
```

## License

Copyright &copy; 2022 Bitnami

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.