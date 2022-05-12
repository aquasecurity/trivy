# kubectl

You can use static YAML manifests to install the operator in the `trivy-system` namespace and configure it to select
all namespaces, except `kube-system` and `trivy-system`.

```
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/{{ git.tag }}/deploy/static/trivy-operator.yaml
```

To confirm that the operator is running, check that the `trivy-operator` Deployment in the `trivy-system`
namespace is available and all its containers are ready:

```console
$ kubectl get deployment -n trivy-system
NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
trivy-operator   1/1     1            1           11m
```

If for some reason it's not ready yet, check the logs of the `trivy-operator` Deployment for errors:

```
kubectl logs deployment/trivy-operator -n trivy-system
```

Trivy-Operator ensures the default [Settings] stored in ConfigMaps and Secrets created in the `trivy-system` namespace.
You can always change these settings by editing configuration objects. For example, you can use Trivy in [ClientServer]
mode, which is more efficient that the [Standalone] mode, or switch to [Aqua Enterprise] as an alternative vulnerability
scanner.

You can further adjust the [Configuration](./../configuration.md) of the operator with environment variables. For
example, to change the target namespace from all namespaces to the `default` namespace edit the `trivy-operator`
Deployment and change the value of the `OPERATOR_TARGET_NAMESPACES` environment variable from the blank string
(`""`) to the `default` value.

Trivy-Operator can generate the compliance report based on the [NSA, CISA Kubernetes Hardening Guidance v1.0]. In order to do
that you must install the `nsa` ClusterComplianceReport resource:

```
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/{{ git.tag }}/deploy/specs/nsa-1.0.yaml
```

Static YAML manifests with fixed values have shortcomings. For example, if you want to change the container image or
modify default configuration settings, you have to edit existing manifests or customize them with tools such as
[Kustomize]. Thus, we also provide [Helm] chart as an alternative installation option.

## Uninstall

!!! danger
    Uninstalling the operator and deleting custom resource definitions will also delete all generated security reports.

You can uninstall the operator with the following command:

```
kubectl delete -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/{{ git.tag }}/deploy/static/trivy-operator.yaml
```

[Settings]: ./../../settings.md
[Standalone]: ./../../vulnerability-scanning/trivy.md#standalone
[ClientServer]: ./../../vulnerability-scanning/trivy.md#clientserver
[Aqua Enterprise]: ./../../vulnerability-scanning/aqua-enterprise.md
[Kustomize]: https://kustomize.io
[Helm]: ./helm.md
[NSA, CISA Kubernetes Hardening Guidance v1.0]: ./../../specs/NSA_Kubernetes_Hardening_Guidance_1.0.pdf
