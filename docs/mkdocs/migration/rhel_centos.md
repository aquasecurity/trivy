Use `https://aquasecurity.github.io` instead of `https://knqyf263.github.io`.

```bash
$ yum remove trivy
$ sed -i s/knqyf263/aquasecurity/g /etc/yum.repos.d/trivy.repo
$ yum update
$ yum install trivy
```
