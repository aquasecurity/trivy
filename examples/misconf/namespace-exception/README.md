# Namespace-based exceptions
`policy/k8s_exception.rego` exempts all policies with `builtin.kubernetes` prefix.
It means all built-in policies for Kubernetes are disabled.

``` bash
$ trivy conf --severity HIGH,CRITICAL --policy ./policy ./configs
2021-07-09T23:40:55.379+0300    INFO    Detected config files: 2

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 21, FAILURES: 2, EXCEPTIONS: 0)
Failures: 2 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Specify at least 1 USER                  |
|                           |            |                      |          | command in Dockerfile with               |
|                           |            |                      |          | non-root user as argument                |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+

deployment.yaml (kubernetes)
============================
Tests: 28 (SUCCESSES: 0, FAILURES: 0, EXCEPTIONS: 28)
Failures: 0 (HIGH: 0, CRITICAL: 0)

```
