# CISKubeBenchReport

The CISKubeBenchReport is a cluster scoped resource owned by a Kubernetes node, which represents the latest result
of running CIS Kubernetes Benchmark tests on that node. It's named after a corresponding node.

The following listing shows a sample CISKubeBenchReport associated with the `kind-control-plane` node.

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: CISKubeBenchReport
metadata:
  name: kind-control-plane
  labels:
    trivy-operator.resource.kind: Node
    trivy-operator.resource.name: kind-control-plane
  uid: 4aec0c8e-c98d-4b53-8727-1e22cacdb772
  ownerReferences:
    - apiVersion: v1
      blockOwnerDeletion: false
      controller: true
      kind: Node
      name: kind-control-plane
      uid: 6941ddfd-65be-4960-8cda-a4d11e53cbe9
report:
  updateTimestamp: '2021-05-20T11:53:58Z'
  scanner:
    name: kube-bench
    vendor: Aqua Security
    version: 0.5.0
  sections:
    - id: '1'
      node_type: master
      tests:
        - desc: Master Node Configuration Files
          fail: 1
          info: 0
          pass: 18
          results:
            - remediation: >
                Run the below command (based on the file location on your
                system) on the

                master node.

                For example, chmod 644
                /etc/kubernetes/manifests/kube-apiserver.yaml
              scored: true
              status: PASS
              test_desc: >-
                Ensure that the API server pod specification file permissions
                are set to 644 or more restrictive (Automated)
              test_number: 1.1.1
            - remediation: >
                Run the below command (based on the file location on your
                system) on the master node.

                For example,

                chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml
              scored: true
              status: PASS
              test_desc: >-
                Ensure that the API server pod specification file ownership is
                set to root:root (Automated)
              test_number: 1.1.2
          section: '1.1'
          warn: 2
      text: Master Node Security Configuration
      total_fail: 10
      total_info: 0
      total_pass: 45
      total_warn: 10
      version: '1.6'
  summary:
    failCount: 11
    infoCount: 0
    passCount: 71
    warnCount: 40
```

!!! note
    We do not anticipate many (at all) kube-bench alike tools, hence the schema of this report is currently the same as
    the output of [kube-bench].

[kube-bench]: https://github.com/aquasecurity/kube-bench
