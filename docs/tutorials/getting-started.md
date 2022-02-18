# Getting started with Trivy

This tutorial will show you how to get started with the Trivy CLI.

**Prerequisites**
* Basic understanding of container technologies and tools such as docker
* docker, podman or similar tool installed

## Installation

In this example we are going to use homebrew to install the Trivy CLI. 

Homebrew can be used on MacOS and Linux.

```bash
brew install aquasecurity/trivy/trivy
```

You can find alternative installation options [here.](installation)

Make sure Trivy is installed by checking the version:

```
$ trivy --version
```

## Eplore the CLI

You can see all the options through running the following command:
```
$ trivy --help
```

<details>
<summary>Result</summary>
```
NAME:
   trivy - A simple and comprehensive vulnerability scanner for containers

USAGE:
   trivy [global options] command [command options] target

VERSION:
   0.23.0

COMMANDS:
   image, i          scan an image
   filesystem, fs    scan local filesystem for language-specific dependencies and config files
   rootfs            scan rootfs
   repository, repo  scan remote repository
   client, c         client mode
   server, s         server mode
   config, conf      scan config files
   plugin, p         manage plugins
   help, h           Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --quiet, -q        suppress progress bar and log output (default: false) [$TRIVY_QUIET]
   --debug, -d        debug mode (default: false) [$TRIVY_DEBUG]
   --cache-dir value  cache directory (default: "/Users/anaisurlichs/Library/Caches/trivy") [$TRIVY_CACHE_DIR]
   --help, -h         show help (default: false)
   --version, -v      print the version (default: false)
```
</details>


In this tutorial, we are focusing on 
* Scanning container images
* Scanning IaC configuration files
* Scanning Git Repositories

## Scan container image

Simply specify an image name (and a tag). Learn more about container images and how to use them [here.](containers)
If you don't specifiy the tag, it will check the latest image on the Container Registry.

```
$ trivy image [YOUR_IMAGE_NAME]
```

For example:

```
$ trivy image python:3.4-alpine
```

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

For more details, see [here][vulnerability].

## Scan directory for misconfigurations

Simply specify a directory containing IaC files such as Terraform or a Dockerfile.

```
$ trivy config [YOUR_IAC_DIR]
```

For example:

```
$ ls build/
Dockerfile
$ trivy config ./build
```

<details>
<summary>Result</summary>

```
2021-07-09T10:06:29.188+0300    INFO    Need to update the built-in policies
2021-07-09T10:06:29.188+0300    INFO    Downloading the built-in policies...
2021-07-09T10:06:30.520+0300    INFO    Detected config files: 1

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
|                           |            |                      |          | Dockerfile should not be 'root'          |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+
```

</details>

For more details, see [here][misconf].

## Scan Git repository for misconfigurations

Trivy allows you to scan a Git repository for misconfigurations and vulnerabilities:

```
$ trivy repo [GIT_REPOSITORY_URL]
```

For example:

```
$ trivy repo https://github.com/knqyf263/trivy-ci-test
```

<details>
<summary>Result</summary>

```
Enumerating objects: 25, done.
Counting objects: 100% (25/25), done.
Compressing objects: 100% (18/18), done.
Total 25 (delta 4), reused 19 (delta 2), pack-reused 0
2022-02-18T11:33:13.280Z	INFO	Number of language-specific files: 2
2022-02-18T11:33:13.280Z	INFO	Detecting cargo vulnerabilities...
2022-02-18T11:33:13.282Z	INFO	Detecting pipenv vulnerabilities...

Cargo.lock (cargo)
==================
Total: 9 (UNKNOWN: 2, LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 4)

+-----------+-------------------+----------+-------------------+---------------+--------------------------------------------+
|  LIBRARY  | VULNERABILITY ID  | SEVERITY | INSTALLED VERSION | FIXED VERSION |                   TITLE                    |
+-----------+-------------------+----------+-------------------+---------------+--------------------------------------------+
| ammonia   | CVE-2019-15542    | HIGH     | 1.9.0             | 2.1.0         | Uncontrolled recursion leads               |
|           |                   |          |                   |               | to abort in HTML serialization             |
|           |                   |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-15542      |
```

</details>


[vulnerability]: ../how-to-guides/vulnerability/scanning/index.md
[misconf]: ../how-to-guides/misconfiguration/index.md
[installation]: ./instalaltion.md

[containers]: https://www.docker.com/resources/what-container


