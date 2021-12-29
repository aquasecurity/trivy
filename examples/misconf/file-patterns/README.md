# File patterns
`configs` dir contains two config files, which do not match the default file patterns.

As you can see, no config files are detected.

```bash
$ trivy conf --severity HIGH,CRITICAL configs
2021-07-10T19:37:22.739+0300    INFO    Detected config files: 0
```

In this case, you can use `--file-patterns` option.

```bash
$ trivy conf --file-patterns "dockerfile:.*.docker" --file-patterns "yaml:deployment" configs
trivy conf --severity HIGH,CRITICAL --file-patterns "dockerfile:.*.docker" --file-patterns "yaml:deployment" configs
2021-07-10T19:39:29.723+0300    INFO    Detected config files: 2

app.docker (dockerfile)
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

deployment (kubernetes)
=======================
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
