# Attesting Image Scans With Kyverno

This tutorial is based on the following blog post by Chip Zoller: [Attesting Image Scans With Kyverno](https://neonmirrors.net/post/2022-07/attesting-image-scans-kyverno/)

This tutorial details 
- Scan your container image for vulnerabilities
- Generate an attestation with Cosign
- Verify the container image has an attestation with Kyverno

#### Prerequisites
1. Trivy CLI installed
2. Cosign installed 
3. A running Kubernetes cluster that kubectl is connected to

#### Scan Container Image for vulnerabilities

Scan your container image for vulnerabilities and save the scan result to a scan.json file:
```
trivy image --ignore-unfixed --format json --output scan.json anaisurlichs/cns-website:0.0.6
```

* --ignore-unfixed: Ensures that only the vulnerabilities are displayed that have a already a fix available
* --output scan.json: The scan output is scaved to a scan.json file instead of being displayed in the terminal.

Note: Replace the container image with the container image that you would like to scan.

#### Attestation of the vulnerability scan with Cosign

The following command generates an attestation for the vulnerability scan and uploads it to our container image:
```
cosign attest --replace --predicate scan.json --type vuln anaisurlichs/cns-website:0.0.6
```

Note: Replace the container image with the container image that you would like to scan.

#### Kyverno Policy to check attestation

The following policy ensures that the attestation is no older than 168h:

vuln-attestation.yaml
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

#### Apply the policy to your Kubernetes cluster

Ensure that you have Kyverno already deployed and running on your cluster -- for instance throught he Kyverno Helm Chart.

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

