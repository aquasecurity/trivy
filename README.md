<img src="imgs/logo.png" width="300">

[![GitHub release](https://img.shields.io/github/release/knqyf263/trivy.svg)](https://github.com/knqyf263/trivy/releases/latest)
[![CircleCI](https://circleci.com/gh/knqyf263/trivy.svg?style=svg)](https://circleci.com/gh/knqyf263/trivy)
[![Go Report Card](https://goreportcard.com/badge/github.com/knqyf263/trivy)](https://goreportcard.com/report/github.com/knqyf263/trivy)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/knqyf263/trivy/blob/master/LICENSE)

A Simple and Comprehensive Vulnerability Scanner for Containers, Compatible with CI

# Abstract
`Trivy` is a simple and comprehensive vulnerability scanner for containers.
`Trivy` detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, etc.).
`Trivy` is easy to use. Just install the binary and you're ready to scan. It can be scanned just by specifying a container image name.

It is considered to be used in CI. Before pushing to a container registry, you can scan your local container image easily.
See [here](#continuous-integration-ci) for details.


# Features
- Detect comprehensive vulnerabilities
  - OS packages (Alpine, Red Hat Enterprise Linux, CentOS, Debian, Ubuntu)
  - **Application dependencies** (Bundler, Composer, Pipenv, npm)
- Simple
  - Specify only an image name
- Easy installation
  - **No need for prerequirements** such as installation of DB, libraries, etc.
  - `apt-get install`, `yum install` and `brew install` is possible (See [Installation](#installation))
- High accuracy
  - Especially Alpine
- **Compatible with CI**
  - See [CI Example](#continuous-integration-ci)


# Installation

## RHEL/CentOS

Add repository setting to `/etc/yum.repos.d`.

```
$ sudo vim /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://knqyf263.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=0
enabled=1
$ sudo yum -y update
$ sudo yum -y install trivy
```

or

```
$ rpm -ivh https://github.com/knqyf263/trivy/releases/download/v0.0.3/trivy_0.0.3_Linux-64bit.rpm
```

## Debian/Ubuntu

Replace `[CODE_NAME]` with your code name

CODE_NAME: wheezy, jessie, stretch, buster, trusty, xenial, bionic

```
$ sudo apt-get install apt-transport-https gnupg
$ wget -qO - https://knqyf263.github.io/trivy-repo/deb/public.key | sudo apt-key add -
$ echo deb https://knqyf263.github.io/trivy-repo/deb [CODE_NAME] main | sudo tee -a /etc/apt/sources.list
$ sudo apt-get update
$ sudo apt-get install trivy
```

or

```
$ sudo apt-get install rpm
$ wget https://github.com/knqyf263/trivy/releases/download/v0.0.3/trivy_0.0.3_Linux-64bit.deb
$ sudo dpkg -i trivy_0.0.3_Linux-64bit.deb
```

## Mac OS X / Homebrew
You can use homebrew on OS X.
```
$ brew tap knqyf263/trivy
$ brew install knqyf263/trivy/trivy
```

## Binary (Including Windows)
Go to [the releases page](https://github.com/knqyf263/trivy/releases), find the version you want, and download the zip file. Unpack the zip file, and put the binary to somewhere you want (on UNIX-y systems, /usr/local/bin or the like). Make sure it has execution bits turned on. 

## From source

```sh
$ go get -u github.com/knqyf263/trivy
```

# Examples
## Continuous Integration (CI)
Scan your image built in Travis CI/CircleCI. The test will fail if a vulnerability is found. When you don't want to fail the test, specify `--exit-code 0` .

**Note**: The first time take a while (faster by cache after the second time)
### Travis CI

```
$ cat .travis.yml
services:
  - docker

before_install:
  - docker build -t trivy-ci-test:latest .
  - wget https://github.com/knqyf263/trivy/releases/download/v0.0.3/trivy_0.0.3_Linux-64bit.tar.gz
  - tar zxvf trivy_0.0.3_Linux-64bit.tar.gz
script:
  - ./trivy --exit-code 1 --quiet trivy-ci-test:latest
cache:
  directories:
    - $HOME/.cache/trivy
```

example: https://travis-ci.org/knqyf263/trivy-ci-test  
repository: https://github.com/knqyf263/trivy-ci-test

### Circle CI

```
$ cat .circleci/config.yml
jobs:
  build:
    docker:
      - image: docker:18.09-git
    steps:
      - checkout
      - setup_remote_docker
      - restore_cache:
          key: vulnerability-db
      - run:
          name: Build image
          command: docker build -t trivy-ci-test:latest .
      - run:
          name: Install trivy
          command: |
            wget https://github.com/knqyf263/trivy/releases/download/v0.0.4/trivy_0.0.4_Linux-64bit.tar.gz
            tar zxvf trivy_0.0.4_Linux-64bit.tar.gz
            mv trivy /usr/local/bin
      - run:
          name: Scan the local image with trivy
          command: trivy --exit-code 1 --quiet trivy-ci-test:latest
      - save_cache:
          key: vulnerability-db
          paths:
            - $HOME/.cache/trivy
workflows:
  version: 2
  release:
    jobs:
      - build
```

example: https://circleci.com/gh/knqyf263/trivy-ci-test  
repository: https://github.com/knqyf263/trivy-ci-test

# Usage

```
NAME:
  trivy - A simple and comprehensive vulnerability scanner for containers
USAGE:
  trivy [options] image_name
VERSION:
  0.0.3
OPTIONS:
  --format value, -f value    format (table, json) (default: "table")
  --input value, -i value     input file path instead of image name
  --severity value, -s value  severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
  --output value, -o value    output file name
  --exit-code value           Exit code when vulnerabilities were found (default: 0)
  --skip-update               skip db update
  --clean, -c                 clean all cache
  --quiet, -q                 suppress progress bar
  --ignore-unfixed            display only fixed vulnerabilities
  --refresh                   refresh DB (usually used after version update of trivy
  --debug, -d                 debug mode
  --help, -h                  show help
  --version, -v               print the version
```

# Q&A
## Homebrew
### Error: Your macOS keychain GitHub credentials do not have sufficient scope!

```
$ brew tap knqyf263/trivy
Error: Your macOS keychain GitHub credentials do not have sufficient scope!
Scopes they need: none
Scopes they have:
Create a personal access token:
  https://github.com/settings/tokens/new?scopes=gist,public_repo&description=Homebrew
echo 'export HOMEBREW_GITHUB_API_TOKEN=your_token_here' >> ~/.zshrc
```

Try:
```
$ printf "protocol=https\nhost=github.com\n" | git credential-osxkeychain erase 
```

### Error: knqyf263/trivy/trivy 64 already installed

```
$ brew upgrade
...
Error: knqyf263/trivy/trivy 64 already installed
```

Try:

```
$ brew unlink trivy && brew uninstall trivy
($ rm -rf /usr/local/Cellar/trivy/64)
$ brew install knqyf263/trivy/trivy
```

## Others
### Detected version update of trivy. Please try again with --refresh option
Try again with `--refresh` option

```
$ trivy --refresh alpine:3.9
```

### Unknown error
Try again with `--clean` option

```
$ trivy --clean
```

# Contribute

1. fork a repository: github.com/knqyf263/trivy to github.com/you/repo
2. get original code: `go get github.com/knqyf263/trivy`
3. work on original code
4. add remote to your repo: git remote add myfork https://github.com/you/repo.git
5. push your changes: git push myfork
6. create a new Pull Request

- see [GitHub and Go: forking, pull requests, and go-getting](http://blog.campoy.cat/2014/03/github-and-go-forking-pull-requests-and.html)

----

# Credits
Special thanks to [Tomoya Amachi](https://github.com/tomoyamachi)

# License
MIT

# Author
Teppei Fukuda (knqyf263)
