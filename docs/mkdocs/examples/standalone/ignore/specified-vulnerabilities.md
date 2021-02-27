Use `.trivyignore`.

```
$ cat .trivyignore
# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543

$ trivy image python:3.4-alpine3.9
```

<details>
<summary>Result</summary>

```
2019-05-16T12:53:10.076+0900    INFO    Updating vulnerability database...
2019-05-16T12:53:28.134+0900    INFO    Detecting Alpine vulnerabilities...

python:3.4-alpine3.9 (alpine 3.9.2)
===================================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

```

</details>
