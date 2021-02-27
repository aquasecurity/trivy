Scan a filesystem (such as a host machine, a virtual machine image, or an unpacked container image filesystem).

Trivy will look for vulnerabilities based on lock files such as Gemfile.lock and package-lock.json.

```
$ trivy fs /path/to/project
```

Scan your container from inside the container.

```
$ docker run --rm -it alpine:3.11
/ # curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
/ # trivy fs /
```
