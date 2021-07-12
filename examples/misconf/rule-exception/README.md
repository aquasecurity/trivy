# Rule-based exceptions

## Without exception
If any exceptions are not specified, KSV006 is detected in both files.

``` bash
$ trivy conf --severity HIGH,CRITICAL ./configs
2021-07-09T23:24:42.834+0300    INFO    Detected config files: 2

deployment-allow.yaml (kubernetes)
==================================
Tests: 28 (SUCCESSES: 14, FAILURES: 13, EXCEPTIONS: 1)
Failures: 13 (HIGH: 0, CRITICAL: 0)

+---------------------------+------------+-------------------------------------+----------+--------------------------------------------------+
|           TYPE            | MISCONF ID |                CHECK                | SEVERITY |                     MESSAGE                      |
+---------------------------+------------+-------------------------------------+----------+--------------------------------------------------+
| Kubernetes Security Check |   KSV006   | docker.sock is mounted to container |   HIGH   | data.appshield.kubernetes.KSV006.exception[_][_] |
|                           |            |                                     |          | == ""                                            |
+---------------------------+------------+-------------------------------------+----------+--------------------------------------------------+

deployment-deny.yaml (kubernetes)
=================================
Tests: 28 (SUCCESSES: 14, FAILURES: 14, EXCEPTIONS: 0)
Failures: 14 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |                CHECK                | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
| Kubernetes Security Check |   KSV006   | docker.sock is mounted to container |   HIGH   | Deployment 'test-deny' should not        |
|                           |            |                                     |          | specify '/var/run/docker.socker' in      |
|                           |            |                                     |          | 'spec.template.volumes.hostPath.path'    |
|                           |            |                                     |          | -->avd.aquasec.com/appshield/ksv006      |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
```

## With exception
`policy` dir contains Rego policy for exempting KSV006.
Needs to pass the directory by `--policy` option.
KSV006 is no longer detected in `deployment-allow.yaml`.

``` bash
$ trivy conf --severity HIGH,CRITICAL --policy ./policy ./configs
2021-07-09T23:32:08.021+0300    INFO    Detected config files: 2

deployment-allow.yaml (kubernetes)
==================================
Tests: 28 (SUCCESSES: 14, FAILURES: 13, EXCEPTIONS: 1)
Failures: 13 (HIGH: 0, CRITICAL: 0)


deployment-deny.yaml (kubernetes)
=================================
Tests: 28 (SUCCESSES: 14, FAILURES: 14, EXCEPTIONS: 0)
Failures: 14 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |                CHECK                | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
| Kubernetes Security Check |   KSV006   | docker.sock is mounted to container |   HIGH   | Deployment 'test-deny' should not        |
|                           |            |                                     |          | specify '/var/run/docker.socker' in      |
|                           |            |                                     |          | 'spec.template.volumes.hostPath.path'    |
|                           |            |                                     |          | -->avd.aquasec.com/appshield/ksv006      |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
```

