# Custom Data
Disallowed ports are defined in `data/ports.yaml`.
They are imported in `policy/custom.rego`.

```
$ trivy conf --severity HIGH,CRITICAL --policy ./policy --data data --namespaces user ./configs
2021-07-10T00:10:21.775+0300    INFO    Detected config files: 1

Dockerfile (dockerfile)
=======================
Tests: 24 (SUCCESSES: 22, FAILURES: 2, EXCEPTIONS: 0)
Failures: 2 (HIGH: 2, CRITICAL: 0)

+---------------------------+------------+--------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |          CHECK           | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+--------------------------+----------+------------------------------------------+
|    Docker Custom Check    |   ID002    | Disallowed ports exposed |   HIGH   | Port 23 should not be exposed            |
+---------------------------+------------+--------------------------+          +------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root'     |          | Specify at least 1 USER                  |
|                           |            |                          |          | command in Dockerfile with               |
|                           |            |                          |          | non-root user as argument                |
|                           |            |                          |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+--------------------------+----------+------------------------------------------+

```