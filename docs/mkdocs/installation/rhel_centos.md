Add repository setting to `/etc/yum.repos.d`.

```
$ sudo vim /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=0
enabled=1
$ sudo yum -y update
$ sudo yum -y install trivy
```

or

```
$ rpm -ivh https://github.com/aquasecurity/trivy/releases/download/{TRIVY_VERSION}/trivy_{TRIVY_VERSION}_Linux-64bit.rpm
```
