# Attesting Image Scans With Kyverno

This tutorial is based on the following blog post by Chip Zoller: [Attesting Image Scans With Kyverno](https://neonmirrors.net/post/2022-07/attesting-image-scans-kyverno/)

This tutorial details 

- Verify the container image has an attestation with Kyverno

### Prerequisites
1. [Attestation of the vulnerability scan uploaded][vuln-attestation]
2. A running Kubernetes cluster that kubectl is connected to

### Kyverno Policy to check attestation

The following policy ensures that the attestation is no older than 168h:

vuln-attestation.yaml

{% raw %}

```bash
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: check-vulnerabilities
spec:
  validationFailureAction: enforce
  webhookTimeoutSeconds: 10
  failurePolicy: Fail
  rules:
    - name: not-older-than-one-week
      match:
        any:
        - resources:
            kinds:
              - Pod
      verifyImages:
      - imageReferences:
        - "CONTAINER-REGISTRY/*:*"
        attestations:
        - predicateType: cosign.sigstore.dev/attestation/vuln/v1
          conditions:
          - all:
            - key: "{{ time_since('','{{metadata.scanFinishedOn}}','') }}"
              operator: LessThanOrEquals
              value: "168h"
```

{% endraw %}

### Apply the policy to your Kubernetes cluster

Ensure that you have Kyverno already deployed and running on your cluster -- for instance through he Kyverno Helm Chart.

Next, apply the above policy:
```
kubectl apply -f vuln-attestation.yaml
```

To ensure that the policy worked, we can deploye an example deployment file with our container image:

deployment.yaml
```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cns-website
  namespace: app
spec:
  replicas: 2
  selector:
    matchLabels:
      run: cns-website
  template:
    metadata:
      labels:
        run: cns-website
    spec:
      containers:
      - name: cns-website
        image: docker.io/anaisurlichs/cns-website:0.0.6
        ports:
          - containerPort: 80
        imagePullPolicy: Always
        resources:
          limits:
            memory: 512Mi
            cpu: 200m
        securityContext:
          allowPrivilegeEscalation: false
```

Once we apply the deployment, it should pass since our attestation is available:
```
kubectl apply -f deployment.yaml -n app
deployment.apps/cns-website created
```

However, if we try to deploy any other container image, our deployment will fail. We can verify this by replacing the image referenced in the deployment with `docker.io/anaisurlichs/cns-website:0.0.5` and applying the deployment:
```
kubectl apply -f deployment-two.yaml

Resource: "apps/v1, Resource=deployments", GroupVersionKind: "apps/v1, Kind=Deployment"
Name: "cns-website", Namespace: "app"
for: "deployment-two.yaml": admission webhook "mutate.kyverno.svc-fail" denied the request: 

resource Deployment/app/cns-website was blocked due to the following policies

check-image:
  autogen-check-image: |
    failed to verify signature for docker.io/anaisurlichs/cns-website:0.0.5: .attestors[0].entries[0].keys: no matching signatures:
```

[vuln-attestation]: ../signing/vuln-attestation.md