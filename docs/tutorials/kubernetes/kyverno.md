# Attesting Image Scans With Kyverno

This tutorial is based on the following blog post by Chip Zoller: [Attesting Image Scans With Kyverno](https://neonmirrors.net/post/2022-07/attesting-image-scans-kyverno/)

This tutorial details 

- Verify the container image has an attestation with Kyverno

### Prerequisites
1. A running Kubernetes cluster that kubectl is connected to
2. A Container image signed with Cosign and an attestation generated for a Trivy Vulnerability scan.
  [Follow this tutorial for more information.][vuln-attestation]

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
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  failurePolicy: Fail
  rules:
    - name: checking-vulnerability-scan-not-older-than-one-hour
      match:
        any:
        - resources:
            kinds:
              - Pod
      verifyImages:
      - imageReferences:
        - "*"
        attestations:
        - type: https://cosign.sigstore.dev/attestation/vuln/v1
          conditions:
          - all:
            - key: "{{ time_since('','{{ metadata.scanFinishedOn }}', '') }}"
              operator: LessThanOrEquals
              value: "1h"
          attestors:
          - count: 1
            entries:
            - keys:
                publicKeys: |-
                  -----BEGIN PUBLIC KEY-----
                  abc
                  xyz
                  -----END PUBLIC KEY-----
```

{% endraw %}

### Apply the policy to your Kubernetes cluster

Ensure that you have Kyverno already deployed and running on your cluster -- for instance through he Kyverno Helm Chart.

Next, apply the above policy:
```
kubectl apply -f vuln-attestation.yaml
```

To ensure that the policy worked, we can deploy an example Kubernetes Pod with our container image:

```
kubectl run app-signed --image= docker.io/anaisurlichs/signed-example@sha256:c5911ac313e0be82a740bd726dc290e655800a9588424ba4e0558c705d1287fd 
```
Note that the image is based on the [signing tutorial.][vuln-attestation]

Once we apply the deployment, it should pass since our attestation is available:
```
kubectl apply -f deployment.yaml -n app
deployment.apps/cns-website created
```

However, if we try to deploy any other container image, our deployment will fail. We can verify this by replacing the image referenced in the deployment with `docker.io/anaisurlichs/cns-website:0.0.5` and applying the deployment:
```
kubectl run app-unsigned --image=docker.io/anaisurlichs/cns-website:0.1.1 

Resource: "apps/v1, Resource=deployments", GroupVersionKind: "apps/v1, Kind=Deployment"
Name: "cns-website", Namespace: "app"
for: "deployment-two.yaml": admission webhook "mutate.kyverno.svc-fail" denied the request: 

resource Deployment/app/cns-website was blocked due to the following policies

check-image:
  autogen-check-image: |
    failed to verify signature for docker.io/anaisurlichs/cns-website:0.0.5: .attestors[0].entries[0].keys: no matching signatures:
```

[vuln-attestation]: ../signing/vuln-attestation.md