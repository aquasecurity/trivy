# Installation

Replace `{TRIVY_VERSION}` with the latest released version of Trivy. You can find the latest releases on this page: https://github.com/aquasecurity/trivy/releases

## RHEL/CentOS

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

## Debian/Ubuntu

Add repository to `/etc/apt/sources.list.d`.

```
$ sudo apt-get install wget apt-transport-https gnupg lsb-release
$ wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
$ echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
$ sudo apt-get update
$ sudo apt-get install trivy
```

or

```
$ wget https://github.com/aquasecurity/trivy/releases/download/{TRIVY_VERSION}/trivy_{TRIVY_VERSION}_Linux-64bit.deb
$ sudo dpkg -i trivy_{TRIVY_VERSION}_Linux-64bit.deb
```



## Arch Linux
Package trivy-bin can be installed from the Arch User Repository. Examples:
```
pikaur -Sy trivy-bin
```
or
```
yay -Sy trivy-bin
```

## Homebrew

You can use homebrew on macOS and Linux.

```
$ brew install aquasecurity/trivy/trivy
```

## Nix/NixOS

You can use nix on Linux or macOS and on others unofficially.

Note that trivy is currently only in the unstable channels.

```
$ nix-env --install trivy
```

Or through your configuration on NixOS or with home-manager as usual


## Install Script
This script downloads Trivy binary based on your OS and architecture.

```
$ curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

## Binary

Get the latest version from [this page](https://github.com/aquasecurity/trivy/releases/latest), and download the archive file for your operating system/architecture. Unpack the archive, and put the binary somewhere in your `$PATH` (on UNIX-y systems, /usr/local/bin or the like). Make sure it has execution bits turned on.

## From source

```sh
$ mkdir -p $GOPATH/src/github.com/aquasecurity
$ cd $GOPATH/src/github.com/aquasecurity
$ git clone https://github.com/aquasecurity/trivy
$ cd trivy/cmd/trivy/
$ export GO111MODULE=on
$ go install
```

## Docker
### Docker Hub
Replace [YOUR_CACHE_DIR] with the cache directory on your machine.

```
$ docker pull aquasec/trivy
```

Example for Linux:

```
$ docker run --rm -v [YOUR_CACHE_DIR]:/root/.cache/ aquasec/trivy [YOUR_IMAGE_NAME]
```

Example for macOS:

```
$ docker run --rm -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy python:3.4-alpine
```

If you would like to scan the image on your host machine, you need to mount `docker.sock`.

```
$ docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy python:3.4-alpine
```

Please re-pull latest `aquasec/trivy` if an error occurred.

<details>
<summary>Result</summary>

```
2019-05-16T01:20:43.180+0900    INFO    Updating vulnerability database...
2019-05-16T01:20:53.029+0900    INFO    Detecting Alpine vulnerabilities...

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

### GitHub Container Registry

The same image is hosted on [GitHub Container Registry][registry] as well.

```
$ docker pull ghcr.io/aquasecurity/trivy:latest
```

[registry]: https://github.com/orgs/aquasecurity/packages/container/package/trivy

### Amazon ECR Public

The same image is hosted on [Amazon ECR Public](https://gallery.ecr.aws/aquasecurity/trivy) as well.

```
$ docker pull public.ecr.aws/aquasecurity/trivy:latest
```
