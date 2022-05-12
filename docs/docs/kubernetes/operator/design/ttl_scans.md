# TTL scans

## Summary

Add an option to automatically delete old security reports. In this first version focus on vulnerability reports but in the long run we could add similar functionality to other reports as well.

## Motivation

In [537](https://github.com/aquasecurity/trivy-operator/issues/537) we talk about a need to run nightly vulnerability scans of CVE:s.
This way we can make sure to get new CVE reports for long time running pods as well.

## Proposal

Add a environment variable to the operator, for example `OPERATOR_VULNERABILITY_SCANNER_REPORT_TTL=86400`, this way we can add other ttl values for other reports as well.
Adding this environment variable would add a annotation to the generated VulnerabilityReport that we can look for.

Create a new controller that looks for changes in vulnerabilityreports and uses [RequeueAfter](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/reconcile#Result) calculated from the TTL annotation.
At startup the operator will look through all existing vulnerabilityreports and delete existing ones where TTL have expired.
If the TTL haven't expired the the vulnerabilityreports will be requeued and automatically checked again when the TTL have expired.

We could calculate the ttl without having creating a new annotation to the reports but the verbosity of showing the users how long each report
got a ttl outweighs the "issue" of generating a new annotation.

### Example

Below you can see a shortened version of the yaml. Notice the `metadata.annotations.trivy-operator.aquasecurity.github.io/report-ttl` which is new.
The operator would automatically apply the `trivy-operator.aquasecurity.github.io/report-ttl` annotation to all new reports that it generates assuming that the environment variable is set.
In theory users could also extend the TTL manually for a specific report by changing the trivy-operator.aquasecurity.github.io/report-ttl annotation per VulnerabilityReport.

```vulnerabilityReport.yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata:
  creationTimestamp: "2021-12-08T12:03:48Z"
  annotations:
    trivy-operator.aquasecurity.github.io/report-ttl: 24h
  labels:
    resource-spec-hash: 86b58dcb99
    trivy-operator.container.name: manager
    trivy-operator.resource.kind: ReplicaSet
    trivy-operator.resource.name: source-controller-b5d5cfdf4
    trivy-operator.resource.namespace: flux-system
  name: replicaset-source-controller-b5d5cfdf4-manager
report:
  artifact:
    repository: fluxcd/source-controller
    tag: v0.16.1
  registry:
    server: ghcr.io
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: 0.19.2
  summary:
    criticalCount: 0
    highCount: 0
    lowCount: 0
    mediumCount: 0
    unknownCount: 0
  updateTimestamp: "2021-12-08T12:03:48Z"
  vulnerabilities: []
```

Another option is to define a new report entry, the positive thing with that is that we can define the input type, in our case a `time.Duration`.

## Alternatives

Another "simpler" option could be to add the same environment variable `OPERATOR_VULNERABILITY_SCANNER_REPORT_TTL=2h` but instead of using RequeueAfter in the controller we could create a cronjob/job that runs once an hour and check for the same annotation.

The bad thing hear is that we would have to manage yet another cronjob/job. We would also have to mange a new binary feature flag to run in cronjob cleanup mode.
It would also trigger removal of multiple reports at the same time, compared to the event driven solution that would be much more precise per report
and thus spreading out the new reports more.

But the good thing is that everyone knows how jobs/cronjobs works especially since it's already well used within the trivy-operator operator.
