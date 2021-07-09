# Combine

## Scan
The `"combine": true` flag combines files into one input data structure.
It allows you to compare multiple values from different configurations simultaneously.

This example compares the values in `deployment.yaml` and `service.yaml`.

``` bash
$ trivy conf --severity CRITICAL --policy ./policy --namespaces user ./configs
2021-07-10T01:22:46.477+0300    INFO    Detected config files: 2

deployment.yaml (kubernetes)
============================
Tests: 29 (SUCCESSES: 17, FAILURES: 12, EXCEPTIONS: 0)
Failures: 12 (CRITICAL: 0)


service.yaml (kubernetes)
=========================
Tests: 29 (SUCCESSES: 28, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (CRITICAL: 1)

+-------------------------+------------+------------------------------------+----------+------------------------------------------+
|          TYPE           | MISCONF ID |               CHECK                | SEVERITY |                 MESSAGE                  |
+-------------------------+------------+------------------------------------+----------+------------------------------------------+
| Kubernetes Custom Check |   ID003    | Servide does not target Pod        | CRITICAL | Service 'my-nginx' selector does not     |
|                         |            |                                    |          | match with any Pod label                 |
+-------------------------+------------+------------------------------------+----------+------------------------------------------+
```