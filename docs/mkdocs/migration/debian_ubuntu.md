Use `https://aquasecurity.github.io` instead of `https://knqyf263.github.io`.

```bash
$ apt-get remove --purge trivy
$ sed -i s/knqyf263/aquasecurity/g /etc/apt/sources.list.d/trivy.list
$ apt-get update
$ apt-get install trivy
```
