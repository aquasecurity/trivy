# Run Vulnerability Scan Job in Same namespace of workload

## Overview 

When user runs a workload with private managed registry image(eg. image from ECR, ACR) and user is not using ImagePullSecret
method to provide access to registry, then trivy operator has challenges to scan such workloads. 
- Consider an example of ECR registry, there is one option available in which that user can associate IAM role to service account,
 then workloads which are associated with this service account will get authorised to run with the image from that registry. 
 If user wants to get these images scanned using Trivy operator then currently we have only one way to do that. 
 User has to associate IAM role to trivy-operator service account, so with when scan job run with `trivy-operator`service 
 account, then Trivy will get appropriate permission to pull the image. To know more on how this mechanism works, please 
 refer to the documents [ECR registry configuration], [IAM role to service account], but, trivy cannot use permission 
 set on service account of workload.  

Recently, there is one option added in Trivy plugin with [Trivy fs command], In which Trivy scans the image which is 
cached on a node. And to do that scan job is scheduled on same node where workload is running, so that Trivy can use a 
cached image from a node. But, if we want to schedule these scan job on any node, then currently we dont have option to 
do that, coz image might not be available on that node. Also, trivy cannot attach imagePullSecret available on the 
workload pull the image. We also thought that when we have ImagePullSecret available on a workload, then we can use existing 
option of Trivy image scan with which we can scan workload. To do that, trivy operator creates another secret 
from existing ImagePullSecret so that registry credentials are provided to Trivy as Env var. But again, 
we cannot reuse the same ImagePullSecret available on the workload.     

## Solution

Consider there is an option given to enable running vulnerability scan jobs in the same namespace of workload. Operator
detects it, so it can schedule and monitor scan jobs in same namespace where workload is running. And plugins will act 
accordingly to utilize the service account and ImagePullSecret available on the workload.


### Example

##### Example 1
Consider trivy operator is running with Trivy image scan mode. And let's assume that there is an `nginx` 
deployment in `poc-ns` namespace. It is running with image `12344534.dkr.ecr.us-west-2.amazonaws.com/amazon/nginx:1.16`. 
This deployment is running with service account `poc-sa`, which is annotated with ARN: `arn:aws:iam::<ACCOUNT_ID>:role/IAM_ROLE_NAME`

   
```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: poc-ns
---
apiVersion: v1
automountServiceAccountToken: true
kind: ServiceAccount
metadata:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/IAM_ROLE_NAME
  name: poc-sa
  namespace: poc-ns
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
      serviceAccountName: poc-sa
      containers:
        - name: nginx
          image: 12344534.dkr.ecr.us-west-2.amazonaws.com/amazon/nginx:1.16
```

> When a pod(`nginx-65b78bbbd4-nb5kl`) comes into running state from above deployment then pod will 
> have these env var to get access to ECR registry: `AWS_REGION`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` 

To scan the `nginx` deployment, trivy-operator create following scan job in `poc-ns` namespace. And trivy-operator
will monitor this job, and it will parse the result based on completion state of job. This job will run with same 
service account(`poc-sa`) of workload.

```yaml
---
apiVersion: batch/v1
kind: Job
metadata:
  name: scan-vulnerabilityreport-ab3134
  namespace: poc-ns
spec:
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: poc-sa
      restartPolicy: Never
      containers:
      # containers from pod spec returned from existing Trivy plugin
```
> When a pod(`scan-vulnerabilityreport-ab3134-nfkst`) gets created from above job spec, then that pod will get injected 
> with these env var which will help scanner to get access to registry image: `AWS_REGION`, `AWS_ROLE_ARN`, 
> `AWS_WEB_IDENTITY_TOKEN_FILE`

Pod will get injected with respective env vars to get access to registry image and Trivy scanner will use these
credentials to pull an image for scanning.


##### Example 2

Consider another example, in which we want to perform vulnerability scan using Trivy `fs` command.
Deployment `demo-nginx` is running in `poc-ns` namespace. This deployment is running with image 
`example.registry.com/nginx:1.16` from private registry `example.registry.com`. Registry credentials are stored in 
ImagePullSecret `private-registry`. 
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
    app: demo-nginx
  name: demo-nginx
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

To scan the `demo-nginx` deployment, trivy-operator create following scan job in `poc-ns` namespace. And trivy-operator 
will monitor job, and it will parse the result based on completion state of job.

```yaml
---
apiVersion: batch/v1
kind: Job
metadata:
  name: scan-vulnerabilityreport-ab3134
  namespace: poc-ns
spec:
  backoffLimit: 0
  template:
    spec:
      # ImagePullSecret value will be copied from workload which we are scanning
      imagePullSecrets:
        - name: private-registry
      restartPolicy: Never
      volumes:
        - name: scan-volume
          emptyDir: { }
      initContainers:
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
        - name: nginx
          image: example.registry.com/nginx:1.16
          imagePullPolicy: IfNotPresent
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

If you observe in the job spec, this scan job will run in `poc-ns` namespace and it is running with image 
`example.registry.com/nginx:1.16`. It is using ImagePullSecret `private-registry` which is available in same namespace. 
With this approach trivy operator will not have to worry about managing(create/delete) of secret required for scanning. 

## Notes
1. There are some points to consider before using this option
    - Scan jobs will run in different namespaces. This will create some activity in each namespace available in the cluster. 
    If we dont use this option then all scan jobs will only run in `trivy-operator` namespace, and user can see all 
    activity confined to single namespace i.e `trivy-operator`.
    - As we will run scan job with service account of workload and if there are some very strict PSP defined in the cluster
    then scan job will be blocked due to the PSP.
  

[ECR registry configuration]: https://aquasecurity.github.io/trivy-operator/v0.14.0/integrations/managed-registries/#amazon-elastic-container-registry-ecr
[IAM role to service account]: https://docs.aws.amazon.com/eks/latest/userguide/specify-service-account-role.html
[Trivy fs command]: https://github.com/aquasecurity/trivy-operator/blob/main/docs/design/design_trivy_file_system_scanner.md
