# Kubernetes

```
$ trivy conf --severity HIGH,CRITICAL --policy ./policy --namespaces user ./configs

2021-07-09T23:46:58.479+0300    INFO    Detected config files: 1

deployment.yaml (kubernetes)
============================
Tests: 29 (SUCCESSES: 14, FAILURES: 15, EXCEPTIONS: 0)
Failures: 15 (HIGH: 2, CRITICAL: 0)

+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |                CHECK                | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
|  Kubernetes Custom Check  |   ID001    | Deployment not allowed              |   HIGH   | Found deployment 'test-deny' but         |
|                           |            |                                     |          | deployments are not allowed              |
+---------------------------+------------+-------------------------------------+          +------------------------------------------+
| Kubernetes Security Check |   KSV006   | docker.sock is mounted to container |          | Deployment 'test-deny' should not        |
|                           |            |                                     |          | specify '/var/run/docker.socker' in      |
|                           |            |                                     |          | 'spec.template.volumes.hostPath.path'    |
|                           |            |                                     |          | -->avd.aquasec.com/appshield/ksv006      |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
```