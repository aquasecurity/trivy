# kubectl

Kubernetes Yaml deployment files are available on GitHub in [https://github.com/aquasecurity/trivy-operator](https://github.com/aquasecurity/trivy-operator) under `/deploy/static`.

## Example - Deploy from GitHub

This will install the operator in the `trivy-system` namespace and configure it to scan all namespaces, except `kube-system` and `trivy-system`:

```bash
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/{{ git.tag }}/deploy/static/trivy-operator.yaml
```

To confirm that the operator is running, check that the `trivy-operator` Deployment in the `trivy-system`
namespace is available and all its containers are ready:

```bash
$ kubectl get deployment -n trivy-system
NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
trivy-operator   1/1     1            1           11m
```

If for some reason it's not ready yet, check the logs of the `trivy-operator` Deployment for errors:

```bash
kubectl logs deployment/trivy-operator -n trivy-system
```

## Advanced Configuration

Trivy-Operator refers to the [settings] configured in ConfigMaps and Secrets under the `trivy-system` namespace. You can always change these settings by editing configuration objects.

You can further adjust the [Configuration](./../configuration.md) of the operator with environment variables. For example, to change the target namespace from all namespaces to the `default` namespace edit the `trivy-operator` Deployment and change the value of the `OPERATOR_TARGET_NAMESPACES` environment variable from the blank string (`""`) to the `default` value.

## Uninstall

!!! danger
    Uninstalling the operator and deleting custom resource definitions will also delete all generated security reports.

You can uninstall the operator with the following command:

```
kubectl delete -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/{{ git.tag }}/deploy/static/trivy-operator.yaml
```

[Settings]: ./../../settings.md
[Helm]: ./helm.md
