```
$ cat Dockerfile
FROM alpine:3.7

RUN apk add curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && trivy filesystem --exit-code 1 --no-progress /

$ docker build -t vulnerable-image .
```

<details>
<summary>Result</summary>

```
Sending build context to Docker daemon  31.14MB
Step 1/2 : FROM alpine:3.7
 ---> 6d1ef012b567
Step 2/2 : RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && trivy filesystem --exit-code 1 --no-progress /
 ---> Running in 27b004205da0
2020-06-01T14:10:41.261Z        INFO    Need to update DB
2020-06-01T14:10:41.262Z        INFO    Downloading DB...
2020-06-01T14:10:56.188Z        INFO    Detecting Alpine vulnerabilities...
2020-06-01T14:10:56.188Z        WARN    This OS version is no longer supported by the distribution: alpine 3.7.3
2020-06-01T14:10:56.188Z        WARN    The vulnerability detection may be insufficient because security updates are not provided

27b004205da0 (alpine 3.7.3)
===========================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| musl    | CVE-2019-14697   | HIGH     | 1.1.18-r3         | 1.1.18-r4     | musl libc through 1.1.23       |
|         |                  |          |                   |               | has an x87 floating-point      |
|         |                  |          |                   |               | stack adjustment imbalance,    |
|         |                  |          |                   |               | related...                     |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
The command '/bin/sh -c trivy filesystem --exit-code 1 --no-progress /' returned a non-zero code: 1
```

</details>
