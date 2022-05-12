# Manage Access to Security Reports

In Trivy-Operator security reports are stored as [CRD] instances (e.g. VulnerabilityReport and ConfigAuditReport objects).

With Kubernetes [RBAC], a cluster administrator can choose the following levels of granularity to manage access to
security reports:

1. Grant **administrative** access to view **any** report in **any** namespace.
2. Grant **coarse-grained** access to view **any** report in a **specified** namespace.
3. Grant **fine-grained** access to view a **specified** report in a **specified** namespace.

Even though you can achieve fine-grained access control with Kubernetes RBAC configuration, it is very impractical to do
so with security reports. Mainly because security reports are associated with ephemeral Kubernetes objects such as Pods
and ReplicaSets.

To sum up, we only recommend using administrative and coarse-grained levels to manage access to security reports.

Continue reading to see examples of managing access to VulnerabilityReport objects at different levels of granularity.

## Create Namespaces and Deployments

Let's consider a multitenant cluster with two `nginx` Deployments in `foo` and `bar` namespaces. There's also the
`redis` Deployment in the `foo` namespace.

```
kubectl create namespace foo
kubectl create deploy nginx --image nginx:1.16 --namespace foo
kubectl create deploy redis --image redis:5 --namespace foo
```

```
kubectl create namespace bar
kubectl create deploy nginx --image nginx:1.16 --namespace bar
```

When we scan them Trivy-Operator will create VulnerabilityReports which are named by revision kind (`replicaset`)
concatenated with revision name (`nginx-7967dc8bfd`) and container name (`nginx`).

```
starboard scan vulnerabilityreports deploy/nginx --namespace foo
starboard scan vulnerabilityreports deploy/redis --namespace foo
starboard scan vulnerabilityreports deploy/nginx --namespace bar
```

!!! tip
    For workloads with multiple containers we'll have multiple instances of VulnerabilityReports with the same prefix
    (`replicaset-nginx-7967dc8bfd-`) but different suffixes that correspond to container names.

```console
$ kubectl tree deploy nginx --namespace foo
NAMESPACE  NAME                                                       READY  REASON  AGE
foo        Deployment/nginx                                           -              21m
foo        └─ReplicaSet/nginx-7967dc8bfd                              -              21m
foo          ├─Pod/nginx-7967dc8bfd-gqw8h                             True           21m
foo          └─VulnerabilityReport/replicaset-nginx-7967dc8bfd-nginx  -              4m36s
```

```console
$ kubectl tree deploy nginx --namespace bar
NAMESPACE  NAME                                                      READY  REASON  AGE
bar        Deployment/nginx                                          -              20m
bar        └─ReplicaSet/nginx-f4cc56f6b                              -              20m
bar          ├─Pod/nginx-f4cc56f6b-9cd45                             True           20m
bar          └─VulnerabilityReport/replicaset-nginx-f4cc56f6b-nginx  -              2m12s
```



```console
$ kubectl tree deploy redis --namespace foo
NAMESPACE  NAME                                                       READY  REASON  AGE
foo        Deployment/redis                                           -              74m
foo        └─ReplicaSet/redis-79c5cc7cf8                              -              74m
foo          ├─Pod/redis-79c5cc7cf8-fz99f                             True           74m
foo          └─VulnerabilityReport/replicaset-redis-79c5cc7cf8-redis  -              74m
```

## Choose Access Level

To manage access to VulnerabilityReport instances a cluster administrator will typically create Role or ClusterRole
objects and bind them to subjects (users, groups, or service accounts) by creating RoleBinding or ClusterRoleBinding
objects.

With Kubernetes RBAC there are three different granularity levels at which you can grant access to VulnerabilityReports:

1. [Cluster - a subject can view **any** report in **any** namespace](#grant-access-to-view-any-vulnerabilityreport-in-any-namespace)
2. [Namespace - a subject can view **any** report in a **specified** namespace](#grant-access-to-view-any-vulnerabilityreport-in-the-foo-namespace)
3. [Security Report - a subject can view a **specified** report in a **specified** namespace](#grant-access-to-view-the-replicaset-nginx-7967dc8bfd-nginx-vulnerabilityreport-in-the-foo-namespace)

## Grant Access to View any VulnerabilityReport in any Namespace

```
kubectl create clusterrole view-vulnerabilityreports \
  --resource vulnerabilityreports \
  --verb get,list,watch
```

```
kubectl create clusterrolebinding dpacak-can-view-vulnerabilityreports \
  --clusterrole view-vulnerabilityreports \
  --user dpacak
```

```console
$ kubectl get vulnerabilityreports -A --as dpacak
NAMESPACE   NAME                                REPOSITORY      TAG    SCANNER   AGE
bar         replicaset-nginx-f4cc56f6b-nginx    library/nginx   1.16   Trivy     40m
foo         replicaset-nginx-7967dc8bfd-nginx   library/nginx   1.16   Trivy     43m
```

```console
$ kubectl get vulnerabilityreports -A --as zpacak
Error from server (Forbidden): vulnerabilityreports.aquasecurity.github.io is f
orbidden: User "zpacak" cannot list resource "vulnerabilityreports" in API grou
p "aquasecurity.github.io" at the cluster scope
```

```console
$ kubectl who-can get vulnerabilityreports -A
No subjects found with permissions to get vulns assigned through RoleBindings

CLUSTERROLEBINDING                           SUBJECT                    TYPE            SA-NAMESPACE
cluster-admin                                system:masters             Group
dpacak-can-view-vulnerabilityreports         dpacak                     User
system:controller:generic-garbage-collector  generic-garbage-collector  ServiceAccount  kube-system
system:controller:namespace-controller       namespace-controller       ServiceAccount  kube-system
```

!!! note
    The [who-can] command is a kubectl plugin that shows who has RBAC permissions to perform actions on different
    resources in Kubernetes.

## Grant Access to View any VulnerabilityReport in the foo Namespace

```
kubectl create clusterrole view-vulnerabilityreports \
  --resource vulnerabilityreports \
  --verb get,list,watch
```

```
kubectl create rolebinding dpacak-can-view-vulnerabilityreports \
  --namespace foo \
  --clusterrole view-vulnerabilityreports \
  --user dpacak
```

```console
$ kubectl get vulnerabilityreports --namespace foo --as dpacak
NAME                                REPOSITORY      TAG    SCANNER   AGE
replicaset-nginx-7967dc8bfd-nginx   library/nginx   1.16   Trivy     51m
```

```console
$ kubectl get vulnerabilityreports --namespace bar --as dpacak
Error from server (Forbidden): vulnerabilityreports.aquasecurity.github.io is f
orbidden: User "dpacak" cannot list resource "vulnerabilityreports" in API grou
p "aquasecurity.github.io" in the namespace "bar"
```

## Grant Access to View the replicaset-nginx-7967dc8bfd-nginx VulnerabilityReport in the foo Namespace

Even though you can grant access to a single VulnerabilityReport by specifying its name when you create Role or
ClusterRole objects, in practice it's not manageable for these reasons:

1. The name of a ReplicaSet (e.g. `nginx-7967dc8bfd`) and hence the name of the corresponding VulnerabilityReport (e.g.
   `replicaset-nginx-7967dc8bfd-nginx`) change over time. This requires that Role or ClusterObject will be updated
   respectively.
2. We create a VulnerabilityReport for each container of a Kubernetes workload. Therefore, managing such fine-grained
   permissions is even more cumbersome.
3. Last but not least, the naming convention is an implementation details that's likely to change when we add support
   for mutable tags or implement caching of scan results.

```
kubectl create role view-replicaset-nginx-7967dc8bfd-nginx \
  --namespace foo \
  --resource vulnerabilityreports \
  --resource-name replicaset-nginx-7967dc8bfd-nginx \
  --verb get
```

```
kubectl create rolebinding dpacak-can-view-replicaset-nginx-7967dc8bfd-nginx \
  --namespace foo \
  --role view-replicaset-nginx-7967dc8bfd-nginx \
  --user dpacak
```

```console
$ kubectl get vuln -n foo replicaset-nginx-7967dc8bfd-nginx --as dpacak
NAME                                REPOSITORY      TAG    SCANNER   AGE
replicaset-nginx-7967dc8bfd-nginx   library/nginx   1.16   Trivy     163m
```

```console
$ kubectl get vuln -n foo replicaset-redis-79c5cc7cf8-redis --as dpacak
Error from server (Forbidden): vulnerabilityreports.aquasecurity.github.io "rep
licaset-redis-79c5cc7cf8-redis" is forbidden: User "dpacak" cannot get resource
"vulnerabilityreports" in API group "aquasecurity.github.io" in the namespace "
foo"
```

```console
$ kubectl who-can get vuln/replicaset-nginx-7967dc8bfd-nginx -n foo
ROLEBINDING                                        NAMESPACE  SUBJECT  TYPE  SA-NAMESPACE
dpacak-can-view-replicaset-nginx-7967dc8bfd-nginx  foo        dpacak   User

CLUSTERROLEBINDING                           SUBJECT                    TYPE            SA-NAMESPACE
cluster-admin                                system:masters             Group
system:controller:generic-garbage-collector  generic-garbage-collector  ServiceAccount  kube-system
system:controller:namespace-controller       namespace-controller       ServiceAccount  kube-system
```

[CRD]: ../crds/index.md
[RBAC]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
[who-can]: https://github.com/aquasecurity/kubectl-who-can
