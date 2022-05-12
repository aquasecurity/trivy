# [DRAFT] Caching Scan Results by Image Reference

## TL;DR;

To find vulnerabilities in container images Trivy-Operator creates asynchronous
Kubernetes (K8s) Jobs. Even though running a vulnerability scanner as a K8s
Job is expensive, Trivy-Operator does not reuse scan results in any way.
For example, if a workload refers to the image that has already been scanned,
Trivy-Operator will go ahead and create another (similar) K8s Job.

To some extent, the problem of wasteful and long-running K8s Jobs can be
mitigated by using Trivy-Operator with Trivy in the [ClientServer] mode instead of
the default [Standalone] mode. In this case a configured Trivy server will cache
results of scanning image layers. However, there is still unnecessary overhead
for managing K8s Jobs and communication between Trivy client and server.
(The only real difference is that some Jobs may complete faster for already scanned
images.)

To solve the above-mentioned problems, we could cache scan results by image
reference. For example, a CRD based implementation can store scan results as
instances of ClusterVulnerabilityReport object named after a hash of the
repo digest. An alternative implementation may cache vulnerability reports
in an AWS S3 bucket or a similar key-value store.

## Example

With the proposed cluster-scoped (or global) cache, Trivy-Operator can check if the
image with the specified reference has already been scanned. If yes, it will
just read the corresponding ClusterVulnerabilityReport, copy its payload, and
finally create an instance of a namespaced VulnerabilityReport.

Let's consider two `nginx:1.16` Deployments in two different namespaces `foo`
and `bar`. In the current implementation Trivy-Operator will spin up two K8s Jobs to
run a scanner and eventually create two VulnerabilityReports in `foo` and `bar`
namespaces respectively.

In a cluster where Trivy-Operator is installed for the first time, when we scan the
`nginx` Deployment in the `foo` namespace there's obviously no
ClusterVulnerabilityReport for `nginx:1.16`. Therefore, Trivy-Operator will spin up
a K8s Job and wait for its completion. On completion, it will create a
cluster-scoped ClusterVulnerabilityReport named after the hash of `nginx:1.16`.
It will also create a namespaced VulnerabilityReport named after the current
revision of the `nginx` Deployment.

> **NOTE** Because a repo digest is not a valid name for a K8s API object, we
> may, for example, calculate a (safe) hash of the repo digest and use is as
> name instead.

```console
$ kubectl get clustervulnerabilityreports
No resources found
```

```console
$ trivy-operator scan vulnerabilityreports deploy/nginx -n foo -v 3
I1008 19:58:19.355462   62385 scanner.go:72] Getting Pod template for workload: {Deployment nginx foo}
I1008 19:58:19.358802   62385 scanner.go:89] Checking if images were already scanned
I1008 19:58:19.360411   62385 scanner.go:95] Cached scan reports: 0
I1008 19:58:19.360421   62385 scanner.go:101] Scanning with options: {ScanJobTimeout:0s DeleteScanJob:true}
I1008 19:58:19.365155   62385 runner.go:79] Running task and waiting forever
I1008 19:58:19.365190   62385 runnable_job.go:74] Creating job "trivy-operator/scan-vulnerabilityreport-cbf8c9b99"
I1008 19:58:19.376902   62385 reflector.go:219] Starting reflector *v1.Event (30m0s) from pkg/mod/k8s.io/client-go@v0.22.2/tools/cache/reflector.go:167
I1008 19:58:19.376920   62385 reflector.go:255] Listing and watching *v1.Event from pkg/mod/k8s.io/client-go@v0.22.2/tools/cache/reflector.go:167
I1008 19:58:19.376902   62385 reflector.go:219] Starting reflector *v1.Job (30m0s) from pkg/mod/k8s.io/client-go@v0.22.2/tools/cache/reflector.go:167
I1008 19:58:19.376937   62385 reflector.go:255] Listing and watching *v1.Job from pkg/mod/k8s.io/client-go@v0.22.2/tools/cache/reflector.go:167
I1008 19:58:19.386049   62385 runnable_job.go:130] Event: Created pod: scan-vulnerabilityreport-cbf8c9b99-4nzkb (SuccessfulCreate)
I1008 19:58:51.243554   62385 runnable_job.go:130] Event: Job completed (Completed)
I1008 19:58:51.247251   62385 runnable_job.go:109] Stopping runnable job on task completion with status: Complete
I1008 19:58:51.247273   62385 runner.go:83] Stopping runner on task completion with error: <nil>
I1008 19:58:51.247278   62385 scanner.go:130] Scan job completed: trivy-operator/scan-vulnerabilityreport-cbf8c9b99
I1008 19:58:51.247297   62385 scanner.go:262] Getting logs for nginx container in job: trivy-operator/scan-vulnerabilityreport-cbf8c9b99
I1008 19:58:51.674449   62385 scanner.go:123] Deleting scan job: trivy-operator/scan-vulnerabilityreport-cbf8c9b99
```

Now, if we scan the `nginx` Deployment in the `bar` namespace, Trivy-Operator will
see that there's already a ClusterVulnerabilityReport (`84bcb5cd46`) for the
same image reference `nginx:1.16` and will skip creation of a K8s Job. It will
just read and copy the report as VulnerabilityReport object to the `bar`
namespace.

```console
$ kubectl get clustervulnerabilityreports -o wide
NAME         REPOSITORY      TAG    DIGEST   SCANNER   AGE   CRITICAL   HIGH   MEDIUM   LOW   UNKNOWN
84bcb5cd46   library/nginx   1.16            Trivy     17s   21         50     33       104   0
```

```console
$ trivy-operator scan vulnerabilityreports deploy/nginx -n bar -v 3
I1008 19:59:23.891718   62478 scanner.go:72] Getting Pod template for workload: {Deployment nginx bar}
I1008 19:59:23.895310   62478 scanner.go:89] Checking if image nginx:1.16 was already scanned
I1008 19:59:23.903058   62478 scanner.go:95] Cache hit
I1008 19:59:23.903078   62478 scanner.go:97] Copying ClusterVulnerabilityReport to VulnerabilityReport
```

As you can see, Trivy-Operator eventually created two VulnerabilityReports by spinning
up only one K8s Job.

```console
$ kubectl get vulnerabilityreports -A
NAMESPACE   NAME                                REPOSITORY      TAG    SCANNER   AGE
bar         replicaset-nginx-6d4cf56db6-nginx   library/nginx   1.16   Trivy     5m38s
foo         replicaset-nginx-6d4cf56db6-nginx   library/nginx   1.16   Trivy     6m10s
```

## Life-cycle management

Just like any other cache it's very important that it's up to date and contains the correct information.
To make sure of this we need to have a automated way of automatically cleaning up the ClusterVulnerabilityReport after some time.

My suggestion is to solve this problem just like we did in [PR #879](https://github.com/aquasecurity/trivy-operator/pull/879).
For each ClusterVulnerabilityReport created we should annotate the report with `trivy-operator.aquasecurity.github.io/cluster-vulnerability-report-ttl`.
When the TTL ends the other controller will automatically delete the existing ClusterVulnerabilityReport and the next time the image is created in the cluster and normal vulnerabilityreport scan will happen.

I suggest that we have a default value of 72 hours for this report. This is a new feature and I don't see why we shouldn't enable it by default.

### Vulnerability reports

From a vulnerability reports point of view we need to have a simple way for cluster admins to know if the vulnerability report is generated from a cache and if so which one?

We could ether do this by setting a status on the vulnerability report that gets created but since this feature won't be on by default I suggest we use annotations.

For example: `trivy-operator.aquasecurity.github.io/ClusterVulnerabilityReportName: 84bcb5cd46` would make it easy to find.
We can't use something like ownerReference since it would delete all vulnerabilities at the same time if a ClusterVulnerabilityReport was deleted.

## Summary

* This solution might be the first step towards more efficient vulnerability scanning.
* It's backward compatible and can be implemented as an experimental feature behind
  a gate.
* Both Trivy-Operator CLI and Trivy-Operator Operator can read and leverage ClusterVulnerabilityReports.

[Standalone]: https://aquasecurity.github.io/trivy-operator/v0.12.0/integrations/vulnerability-scanners/trivy/#standalone
[ClientServer]: https://aquasecurity.github.io/trivy-operator/v0.12.0/integrations/vulnerability-scanners/trivy/#clientserver
[PR #879]: (https://github.com/aquasecurity/trivy-operator/pull/879)
