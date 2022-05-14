# Scan Container Images with Trivy Filesystem Scanner

Authors: [Devendra Turkar], [Daniel Pacak]

## Overview

Trivy-Operator currently uses Trivy in [Standalone] or [ClientServer] mode to scan and generate VulnerabilityReports for
container images by pulling the images from remote registries. Trivy-Operator scans a specified K8s workload by running the
Trivy executable as a K8s Job. This approach implies that Trivy does not have access to images cached by the container
runtime on cluster nodes. Therefore, to scan images from private registries Trivy-Operator reads ImagePullSecrets specified
on workloads or on service accounts used by the workloads, and passes them down to Trivy executable as `TRIVY_USERNAME`
and `TRIVY_PASSWORD` environment variables.

Since ImagePullSecrets are not the only way to provide registry credential, the following alternatives are not
currently supported by Trivy-Operator:
1. Pre-pulled images
2. [Configuring nodes to authenticate to a private registry]
3. Vendor-specific or local extension. For example, methods described on [AWS ECR Private registry authentication].

Even though we could resolve some of above-mentioned limitations with hostPath volume mounts to the container runtime
socket, it would have its own disadvantages that we are trying to avoid. For example, more permissions to schedule scan
Jobs and additional information about cluster's infrastructure such as location of the container runtime socket. 

## Solution

### TL;DR;

Use Trivy filesystem scanning to scan container images. The main idea, which is discussed in this proposal, is to
schedule a scan Job on the same cluster node where the scanned workload. This allows Trivy to scan a filesystem of
the container image which is already cached on that node without pulling the image from a remote registry. What's more,
Trivy will scan container images from private registries without providing registry credentials (as ImagePullSecret or
in any other proprietary way).

### Deep Dive

To scan a container image of a given K8s workload Trivy-Operator will create a corresponding container of a scan Job and
override its entrypoint to invoke Trivy filesystem scanner.

This approach requires Trivy executable to be downloaded and made available to the entrypoint. We'll do that by adding
the init container to the scan Job. Such init container will use the Trivy container image to copy Trivy executable out
to the emptyDir volume, which will be shared with the other containers.

Another init container is required to download Trivy vulnerability database and save it to the mounted shared volume.

Finally, the scan container will use shared volume with the Trivy executable and Trivy database to perform the actual
filesystem scan. (See the provided [Example](#example) to have a better idea of all containers defined by a scan Job and
how they share data via the emptyDir volume.)

> Note that the second init container is required in [Standalone] mode, which is the only mode supported by Trivy
> filesystem scanner at the time of writing this proposal.

We further restrict scan Jobs to run on the same node where scanned Pod is running and never pull images from remote
registries by setting the `ImagePullPolicy` to `Never`. To determine the node for a scan Job Trivy-Operator will list active
Pods controlled by the scanned workload. If the list is not empty it will take the node name from the first Pod,
otherwise it will ignore the workload.

### Example

Let's assume that there's the `nginx` Deployment in the `poc-ns` namespace. It runs the `example.registry.com/nginx:1.16`
container image from a private registry `example.registry.com`. Registry credentials are stored in the `private-registry`
ImagePullSecret. (Alternatively, ImagePullSecret can be attached to a service account referred to by the Deployment.)

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: poc-ns
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: nginx
  name: nginx
  namespace: poc-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      imagePullSecrets:
        - name: private-registry
      containers:
        - name: nginx
          image: example.registry.com/nginx:1.16
``` 

To scan the `nginx` container of the `nginx` Deployment, Trivy-Operator will create the following scan Job in the
`trivy-system` namespace and observe it until it's Completed or Failed.

```yaml
---
apiVersion: batch/v1
kind: Job
metadata:
  name: scan-vulnerabilityreport-ab3134
  namespace: trivy-operator-system
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      # Explicit nodeName indicates our intention to schedule a scan pod
      # on the same cluster node where the nginx workload is running.
      # This could also imply considering taints and tolerations and other
      # properties respected by K8s scheduler.
      nodeName: kind-control-plane
      volumes:
        - name: scan-volume
          emptyDir: { }
      initContainers:
        # The trivy-get-binary init container is used to copy out the trivy executable
        # binary from the upstream Trivy container image, i.e. aquasec/trivy:0.19.2,
        # to a shared emptyDir volume.
        - name: trivy-get-binary
          image: aquasec/trivy:0.19.2
          command:
            - cp
            - -v
            - /usr/local/bin/trivy
            - /var/trivy-operator/trivy
          volumeMounts:
            - name: scan-volume
              mountPath: /var/trivy-operator
        # The trivy-download-db container is using trivy executable binary
        # from the previous step to download Trivy vulnerability database
        # from GitHub releases page.
        # This won't be required once Trivy supports ClientServer mode
        # for the fs subcommand.
        - name: trivy-download-db
          image: aquasec/trivy:0.19.2
          command:
            - /var/trivy-operator/trivy
            - --download-db-only
            - --cache-dir
            - /var/trivy-operator/trivy-db
          volumeMounts:
            - name: scan-volume
              mountPath: /var/trivy-operator
      containers:
        # The nginx container is based on the container image that
        # we want to scan with Trivy. However, it has overwritten command (entrypoint)
        # to invoke trivy file system scan. The scan results are output to stdout
        # in JSON format, so we can parse them and store as VulnerabilityReport.
        - name: nginx
          image: example.registry.com/nginx:1.16
          # To scan image layers cached on a cluster node without pulling
          # it from a remote registry.
          imagePullPolicy: Never
          securityContext:
            # Trivy must run as root, so we set UID here.
            runAsUser: 0
          command:
            - /var/trivy-operator/trivy
            - --cache-dir
            - /var/trivy-operator/trivy-db
            - fs
            - --format
            - json
            - /
          volumeMounts:
            - name: scan-volume
              mountPath: /var/trivy-operator
```

Notice that the scan Job does not use registry credentials stored in the `private-registry` ImagePullSecret at all.
Also, the `ImagePullPolicy` for the `nginx` container is set to `Never` to avoid pulling the image from the
`example.registry.com/nginx` repository that requires authentication. And finally, the `nodeName` property is explicitly
set to `kube-control-plane` to make sure that the scan Job is scheduled on the same node as a Pod controlled by the
`nginx` Deployment. (We assumed that there was at least one Pod controlled by the `nginx` Deployment, and it was scheduled
on the `kube-control-plane` node.)

Trivy must run as root so the scan Job defined the `securityContext` with the `runAsUser` property set to `0` UID.

## Remarks

1. The proposed solution won't work with the [AlwaysPullImages] admission controller, which might be enabled in
   a multitenant cluster so that users can be assured that their private images can only be used by those who
   have the credentials to pull them. (Thanks [kfox1111] for pointing this out!)
2. We cannot scan K8s workloads scaled down to 0 replicas because we cannot infer on which cluster node a scan Job should
   run. (In general, a node name is only set on a running Pod.) But once a workload is scaled up, Trivy Operator
   will receive the update event and will have another chance to scan it.
3. It's hard to identify Pods managed by the CronJob controller, therefore we'll skip them.
4. Trivy filesystem command does not work in [ClientServer] mode. Therefore, this solution is subject to the limits of
   the [Standalone] mode. We plan to extend Trivy filesystem command to work in ClientServer mode and improve the
   implementation of Trivy once it's available.
5. Trivy must run as root and this may be blocked by some Admission Controllers such as PodSecurityPolicy.

[Devendra Turkar]: https://github.com/deven0t
[Daniel Pacak]: https://github.com/danielpacak
[Standalone]: /docs/kubernetes/operator/vulnerability-scanning/trivy/#standalone
[ClientServer]: /docs/kubernetes/operator/vulnerability-scanning/trivy/#standalone
[Configuring nodes to authenticate to a private registry]: https://kubernetes.io/docs/concepts/containers/images/#configuring-nodes-to-authenticate-to-a-private-registry
[AWS ECR Private registry authentication]: https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html
[AlwaysPullImages]: https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages
[kfox1111]: https://github.com/kfox1111

