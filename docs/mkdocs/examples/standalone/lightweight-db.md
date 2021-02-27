The lightweight DB doesn't contain vulnerability detail such as descriptions and references. Because of that, the size of the DB is smaller and the download is faster.

This option is useful when you don't need vulnerability details and is suitable for CI/CD.
To find the additional information, you can search vulnerability details on the NVD website.
https://nvd.nist.gov/vuln/search

```
$ trivy image --light alpine:3.10
```

`--light` option doesn't display titles like the following example.

<details>
<summary>Result</summary>

```
2019-11-14T10:21:01.553+0200    INFO    Reopening vulnerability DB
2019-11-14T10:21:02.574+0200    INFO    Detecting Alpine vulnerabilities...

alpine:3.10 (alpine 3.10.2)
===========================
Total: 3 (UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |
+---------+------------------+----------+-------------------+---------------+
| openssl | CVE-2019-1549    | MEDIUM   | 1.1.1c-r0         | 1.1.1d-r0     |
+         +------------------+          +                   +               +
|         | CVE-2019-1563    |          |                   |               |
+         +------------------+----------+                   +               +
|         | CVE-2019-1547    | LOW      |                   |               |
+---------+------------------+----------+-------------------+---------------+
```
</details>
