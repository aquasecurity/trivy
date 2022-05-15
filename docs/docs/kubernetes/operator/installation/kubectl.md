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

You can configure Trivy-Operator to control it's behavior and adapt it to your needs. Aspects of the operator machinery are configured using environment variables on the operator Pod, while aspects of the scanning behavior are controlled by ConfigMaps and Secrets.
To learn more, please refer to the [Configuration](config) documentation.

## Uninstall

!!! danger
    Uninstalling the operator and deleting custom resource definitions will also delete all generated security reports.

You can uninstall the operator with the following command:

```
kubectl delete -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/{{ git.tag }}/deploy/static/trivy-operator.yaml
```

[Settings]: ./../../settings.md
[Helm]: ./helm.md
