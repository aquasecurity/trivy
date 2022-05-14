# Troubleshooting the Trivy Operator

The Trivy Operator installs several Kubernetes resources into your Kubernetes cluster.

Here are the common steps to check whether the operator is running correctly and to troubleshoot common issues.

In addition to having a look at this section, you want to check [previous issues](https://github.com/aquasecurity/starboard/issues) to see if someone from the community had similar problems before.
Feel free to either [open an issue](https://github.com/aquasecurity/starboard/issues), reach out on [Slack](https://slack.aquasec.com), or post your questions in the [discussion forum.](https://github.com/aquasecurity/starboard/discussions)

## Installation

Make sure that the latest version of the Trivy Operator is installed inside of your Kubernetes cluster.
For this, have a look at the installation [options.](./installation/helm.md)

For instance, if your are using the Helm deployment, you need to check the Helm Chart version deployed to your cluster. You can check the Helm Chart version with the following command:
```
helm list -n <namespace>
```

Please make sure to replace the `namespace` with the namespace to which you installed the Trivy Operator. In the installation guide, we are using `starboard-system` as our namespace.

## Trivy Pod Not Running

The Trivy Operator will run a pod inside your cluster. If you have followed the installation guide, you will have installed the Operator to the `starboard-system`. If you have installed it to another namespace, make sure to adapt the commands below.

Make sure that the pod is in the `Running` status:
```
kubectl get pods -n starboard-system
```

This is how it will look if it is running okay:

```
NAMESPACE            NAME                                         READY   STATUS    RESTARTS      AGE
starboard-system     starboard-operator-6c9bd97d58-hsz4g          1/1     Running   5 (19m ago)   30h
```

If the pod is in `Failed`, `Pending`, or `Unknown` check the events and the logs of the pod.

First, check the events, since they might be more descriptive of the problem. However, if the events do not give a clear reason why the pod cannot spin up, then you want to check the logs, which provide more detail.

```
kubectl describe pod <POD-NAME> -n starboard-system
```

To check the logs, use the following command:
```
kubectl logs deployment/starboard-operator -n starboard-system
```

If your pod is not running, try to look for errors as they can give an indication on the problem.

If there are too many logs messages, try deleting the Trivy pod and observe its behaviour upon restarting. A new pod should spin up automatically after deleting the failed pod.

## ImagePullBackOff or ErrImagePull

Check the status of the Trivy Operator pod running inside of your Kubernetes cluster. If the Status is ImagePullBackOff or ErrImagePull, it means that the Operator either

* tries to access the wrong image
* cannot pull the image from the registry

Make sure that you are providing the right resources upon installing the Trivy Operator.

## CrashLoopBackOff

If your pod is in `CrashLoopBackOff`, it is likely the case that the pod cannot be scheduled on the Kubernetes node that it is trying to schedule on.
In this case, you want to investigate further whether there is an issue with the node. It could for instance be the case that the node does not have sufficient resources.

## Reconcilation Error

It could happen that the pod appears to be running normally but does not reconcile the resources inside of your Kubernetes cluster.

Check the logs for reconcilation errors:
```
kubectl logs deployment/starboard-operator -n starboard-system
```

If this is the case, the Trivy Operator likely does not have the right configurations to access your resource. 

## Operator does not Create VulnerabilityReports

VulnerabilityReports are owned and controlled by the immediate Kubernetes workload. Every VulnerabilityReport of a pod is thus, linked to a [ReplicaSet.](./index.md) In case the Trivy Operator does not create a VulnerabilityReport for your workloads, it could be that it is not monitoring the namespace that your workloads are running on.

An easy way to check this is by looking for the `ClusterRoleBinding` for the Trivy Operator:

```
kubectl get ClusterRoleBinding | grep "starboard-operator"
```

Alternatively, you could use the `kubectl-who-can` [plugin by Aqua](https://github.com/aquasecurity/kubectl-who-can):

```console
$ kubectl who-can list vulnerabilityreports
No subjects found with permissions to list vulnerabilityreports assigned through RoleBindings

CLUSTERROLEBINDING                           SUBJECT                         TYPE            SA-NAMESPACE
cluster-admin                                system:masters                  Group
starboard-operator                           starboard-operator              ServiceAccount  starboard-system
system:controller:generic-garbage-collector  generic-garbage-collector       ServiceAccount  kube-system
system:controller:namespace-controller       namespace-controller            ServiceAccount  kube-system
system:controller:resourcequota-controller   resourcequota-controller        ServiceAccount  kube-system
system:kube-controller-manager               system:kube-controller-manager  User
```

If the `ClusterRoleBinding` does not exist, Trivy currently cannot monitor any namespace outside of the `starboard-system` namespace. 

For instance, if you are using the [Helm Chart](./installation/helm.md), you want to make sure to set the `targetNamespace` to the namespace that you want the Operator to monitor.
