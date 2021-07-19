# Travis CI

```
$ cat .travis.yml
services:
  - docker

env:
  global:
    - COMMIT=${TRAVIS_COMMIT::8}

before_install:
  - docker build -t trivy-ci-test:${COMMIT} .
  - export VERSION=$(curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
  - wget https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz
  - tar zxvf trivy_${VERSION}_Linux-64bit.tar.gz
script:
  - ./trivy --exit-code 0 --severity HIGH --no-progress trivy-ci-test:${COMMIT}
  - ./trivy --exit-code 1 --severity CRITICAL --no-progress trivy-ci-test:${COMMIT}
cache:
  directories:
    - $HOME/.cache/trivy
```

[Example][example]
[Repository][repository]

[example]: https://travis-ci.org/aquasecurity/trivy-ci-test
[repository]: https://github.com/aquasecurity/trivy-ci-test
