# Others

## Exit Code
By default, `Trivy` exits with code 0 even when vulnerabilities are detected.
Use the `--exit-code` option if you want to exit with a non-zero exit code.

```
$ trivy image --exit-code 1 python:3.4-alpine3.9
```

<details>
<summary>Result</summary>

```
2019-05-16T12:51:43.500+0900    INFO    Updating vulnerability database...
2019-05-16T12:52:00.387+0900    INFO    Detecting Alpine vulnerabilities...

python:3.4-alpine3.9 (alpine 3.9.2)
===================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| openssl | CVE-2019-1543    | MEDIUM   | 1.1.1a-r1         | 1.1.1b-r1     | openssl: ChaCha20-Poly1305     |
|         |                  |          |                   |               | with long nonces               |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
```

</details>

This option is useful for CI/CD. In the following example, the test will fail only when a critical vulnerability is found.

```
$ trivy image --exit-code 0 --severity MEDIUM,HIGH ruby:2.4.0
$ trivy image --exit-code 1 --severity CRITICAL ruby:2.4.0
```

## Reset
The `--reset` option removes all caches and database.
After this, it takes a long time as the vulnerability database needs to be rebuilt locally.

```
$ trivy image --reset
```

<details>
<summary>Result</summary>

```
2019-05-16T13:05:31.935+0900    INFO    Resetting...
```

</details>
