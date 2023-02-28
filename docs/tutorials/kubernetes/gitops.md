# Installing the Trivy-Operator through GitOps

This tutorial shows you how to install the Trivy Operator through GitOps platforms, namely ArgoCD and FluxCD.

## ArgoCD

Make sure to have [ArgoCD installed](https://argo-cd.readthedocs.io/en/stable/getting_started/) and running in your Kubernetes cluster.

You can either deploy the Trivy Operator through the argocd CLI or by applying a Kubernetes manifest.

ArgoCD command:
```
> kubectl create ns trivy-system
> argocd app create trivy-operator --repo https://github.com/aquasecurity/trivy-operator --path deploy/helm --dest-server https://kubernetes.default.svc --dest-namespace trivy-system
```
Note that this installation is directly related to our official Helm Chart. If you want to change any of the value, we'd suggest you to create a separate values.yaml file.

Kubernetes manifest `trivy-operator.yaml`:
```
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: trivy-operator
  namespace: argocd
spec:
  project: default
  source:
    chart: trivy-operator
    repoURL: https://aquasecurity.github.io/helm-charts/
    targetRevision: 0.0.3
    helm:
      values: |
        trivy:
          ignoreUnfixed: true
  destination:
    server: https://kubernetes.default.svc
    namespace: trivy-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

The apply the Kubernetes manifest. If you have the manifest locally, you can use the following command through kubectl:
```
> kubectl apply -f trivy-operator.yaml

application.argoproj.io/trivy-operator created
```

If you have the manifest in a Git repository, you can apply it to your cluster through the following command:
```
> kubectl apply -n argocd -f https://raw.githubusercontent.com/AnaisUrlichs/argocd-starboard/main/starboard/argocd-starboard.yaml
```
The latter command would allow you to make changes to the YAML manifest that ArgoCD would register automatically.

Once deployed, you want to tell ArgoCD to sync the application from the actual state to the desired state:
```
argocd app sync trivy-operator
```

Now you can see the deployment in the ArgoCD UI. Have a look at the ArgoCD documentation to know how to access the UI.

![ArgoCD UI after deploying the Trivy Operator](../../imgs/argocd-ui.png)

Note that ArgoCD is unable to show the Trivy CRDs as synced.


## FluxCD

Make sure to have [FluxCD installed](https://fluxcd.io/docs/installation/#install-the-flux-cli) and running in your Kubernetes cluster.

You can either deploy the Trivy Operator through the Flux CLI or by applying a Kubernetes manifest.

Flux command:
```
> kubectl create ns trivy-system
> flux create source helm trivy-operator --url https://aquasecurity.github.io/helm-charts --namespace trivy-system
> flux create helmrelease trivy-operator --chart trivy-operator
  --source HelmRepository/trivy-operator
  --chart-version 0.0.3
  --namespace trivy-system
```

Kubernetes manifest `trivy-operator.yaml`:
```
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: trivy-operator
  namespace: flux-system
spec:
  interval: 60m
  url: https://aquasecurity.github.io/helm-charts/

---
apiVersion: helm.toolkit.fluxcd.io/v2beta1
kind: HelmRelease
metadata:
  name: trivy-operator
  namespace: trivy-system
spec:
  chart:
    spec:
      chart: trivy-operator
      sourceRef:
        kind: HelmRepository
        name: trivy-operator
        namespace: flux-system
      version: 0.10.1
  interval: 60m
  values:
    trivy:
      ignoreUnfixed: true
  install:
    crds: CreateReplace
    createNamespace: true
```

You can then apply the file to your Kubernetes cluster:
```
kubectl apply -f trivy-operator.yaml
```

## After the installation

After the install, you want to check that the Trivy operator is running in the trivy-system namespace:
```
kubectl get deployment -n trivy-system
```

