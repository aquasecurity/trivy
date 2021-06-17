# GitLab CI

_From GitLab 14 and forward, Trivy will be the default scanning tool for containers.
This means that all auto-devops jobs or scripts using the GitLab provided container
scanning templates will automatically use Trivy._


```yaml
stages:
  - test

trivy:
  stage: test
  image: docker:stable
  services:
    - name: docker:dind
      entrypoint: ["env", "-u", "DOCKER_HOST"]
      command: ["dockerd-entrypoint.sh"]
  variables:
    DOCKER_HOST: tcp://docker:2375/
    DOCKER_DRIVER: overlay2
    # See https://github.com/docker-library/docker/pull/166
    DOCKER_TLS_CERTDIR: ""
    IMAGE: trivy-ci-test:$CI_COMMIT_SHA
  before_script:
    - export TRIVY_VERSION=$(wget -qO - "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    - echo $TRIVY_VERSION
    - wget --no-verbose https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz -O - | tar -zxvf -
  allow_failure: true
  script:
    # Build image
    - docker build -t $IMAGE .
    # Build report
    - ./trivy --exit-code 0 --cache-dir .trivycache/ --no-progress --format template --template "@contrib/gitlab.tpl" -o gl-container-scanning-report.json $IMAGE
    # Print report
    - ./trivy --exit-code 0 --cache-dir .trivycache/ --no-progress --severity HIGH $IMAGE
    # Fail on severe vulnerabilities
    - ./trivy --exit-code 1 --cache-dir .trivycache/ --severity CRITICAL --no-progress $IMAGE
  cache:
    paths:
      - .trivycache/
  # Enables https://docs.gitlab.com/ee/user/application_security/container_scanning/ (Container Scanning report is available on GitLab EE Ultimate or GitLab.com Gold)
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

[Example][example]
[Repository][repository]

### GitLab CI using Trivy container

To scan a previously built image that has already been pushed into the
GitLab container registry the following CI job manifest can be used.
Note that `entrypoint` needs to be unset for the `script` section to work.
In case of a non-public GitLab project Trivy additionally needs to
authenticate to the registry to be able to pull your application image.
Finally, it is not necessary to clone the project repo as we only work
with the container image.

```yaml
container_scanning:
  image:
    name: docker.io/aquasec/trivy:latest
    entrypoint: [""]
  variables:
    # No need to clone the repo, we exclusively work on artifacts.  See
    # https://docs.gitlab.com/ee/ci/runners/README.html#git-strategy
    GIT_STRATEGY: none
    TRIVY_USERNAME: "$CI_REGISTRY_USER"
    TRIVY_PASSWORD: "$CI_REGISTRY_PASSWORD"
    TRIVY_AUTH_URL: "$CI_REGISTRY"
    FULL_IMAGE_NAME: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  script:
    - trivy --version
    # cache cleanup is needed when scanning images with the same tags, it does not remove the database
    - time trivy image --clear-cache
    # update vulnerabilities db
    - time trivy --download-db-only --no-progress --cache-dir .trivycache/
    # Builds report and puts it in the default workdir $CI_PROJECT_DIR, so `artifacts:` can take it from there
    - time trivy --exit-code 0 --cache-dir .trivycache/ --no-progress --format template --template "@/contrib/gitlab.tpl"
        --output "$CI_PROJECT_DIR/gl-container-scanning-report.json" "$FULL_IMAGE_NAME"
    # Prints full report
    - time trivy --exit-code 0 --cache-dir .trivycache/ --no-progress "$FULL_IMAGE_NAME"
    # Fail on critical vulnerabilities
    - time trivy --exit-code 1 --cache-dir .trivycache/ --severity CRITICAL --no-progress "$FULL_IMAGE_NAME"
  cache:
    paths:
      - .trivycache/
  # Enables https://docs.gitlab.com/ee/user/application_security/container_scanning/ (Container Scanning report is available on GitLab EE Ultimate or GitLab.com Gold)
  artifacts:
    when:                          always
    reports:
      container_scanning:          gl-container-scanning-report.json
  tags:
    - docker-runner
```

[example]: https://gitlab.com/aquasecurity/trivy-ci-test/pipelines
[repository]: https://github.com/aquasecurity/trivy-ci-test

### Gitlab CI alternative template

Depending on the edition of gitlab you have or your desired workflow, the
container scanning template may not meet your needs. As an addition to the
above container scanning template, a template for
[code climate](https://docs.gitlab.com/ee/user/project/merge_requests/code_quality.html)
has been included. The key things to update from the above examples are
the `template` and `report` type. An updated example is below.

```yaml
stages:
  - test

trivy:
  stage: test
  image: docker:stable
  services:
    - name: docker:dind
      entrypoint: ["env", "-u", "DOCKER_HOST"]
      command: ["dockerd-entrypoint.sh"]
  variables:
    DOCKER_HOST: tcp://docker:2375/
    DOCKER_DRIVER: overlay2
    # See https://github.com/docker-library/docker/pull/166
    DOCKER_TLS_CERTDIR: ""
    IMAGE: trivy-ci-test:$CI_COMMIT_SHA
  before_script:
    - export TRIVY_VERSION=$(wget -qO - "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    - echo $TRIVY_VERSION
    - wget --no-verbose https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz -O - | tar -zxvf -
  allow_failure: true
  script:
    # Build image
    - docker build -t $IMAGE .
    # Build report
    - ./trivy --exit-code 0 --cache-dir .trivycache/ --no-progress --format template --template "@contrib/gitlab-codeclimate.tpl" -o gl-codeclimate.json $IMAGE
  cache:
    paths:
      - .trivycache/
  # Enables https://docs.gitlab.com/ee/user/application_security/container_scanning/ (Container Scanning report is available on GitLab EE Ultimate or GitLab.com Gold)
  artifacts:
    paths:
      gl-codeclimate.json
    reports:
      codequality: gl-codeclimate.json
```

Currently gitlab only supports a single code quality report. There is an
open [feature request](https://gitlab.com/gitlab-org/gitlab/-/issues/9014)
to support multiple reports. Until this has been implemented, if you
already have a code quality report in your pipeline, you can use
`jq` to combine reports. Depending on how you name your artifacts, it may
be necessary to rename the artifact if you want to reuse the name. To then
combine the previous artifact with the output of trivy, the following `jq`
command can be used, `jq -s 'add' prev-codeclimate.json trivy-codeclimate.json > gl-codeclimate.json`.

### GitLab CI remote Trivy server

Trivy can run as a server, allowing clients to connect to it and test images without
having to download any database and keeping the cache intact. This might sometimes be a 
preferable way of doing it.

The following example makes use of a remote Trivy server:

```yaml
stages:
  - scan

image_scan.trivy.remote:
  stage: scan
  image:
    name: docker.io/aquasec/trivy:latest
    entrypoint:
      - ""
  variables:
    GIT_STRATEGY: none
    SCANNING_IMAGE_NAME: "${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}"
    TRIVY_TEMPLATE: "/contrib/gitlab.tpl"
  script:
    - trivy client --remote=${TRIVY_ENDPOINT} --template "@/contrib/gitlab.tpl" --format=template ${SCANNING_IMAGE_NAME} 
    - trivy client --exit-code 1 --remote=${TRIVY_ENDPOINT} --severity HIGH,CRITICAL -o table ${SCANNING_IMAGE_NAME}
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

_Note:  
If you don't want **everyone** to have access to your trivy server, be sure
to secure it with something like `basic auth`, making it easy for the client
to reach the server (with basic auth in the uri) and secure enough for the public
net!_

### GitLab CI dependency scanning

Trivy is not only a tool for image scanning, it also has the ability to scan the 
local file system for dependencies as well!  
Due to the template engine in Trivy, we can easily produce a dependency scan 
file for gitlab as well.

The following script will automatically start and scan for dependencies when finding
a file which Trivy can scan:

```yaml
stages:
  - test

ds_scan.trivy:
  stage:
    - test
  variables:
    TRIVY_CACHE_DIR: "${CI_PROJECT_DIR}/.trivycache"
    TRIVY_VULN_TYPE: "library"
  before_script:
    - mkdir -p ${TRIVY_CACHE_DIR}
    - trivy --download-db-only --cache-dir ${TRIVY_CACHE_DIR}
  script:
    - trivy fs --exit-code 0 --format template --template "@/contrib/gitlab-ds.tpl" -o "${CI_PROJECT_DIR}/gl-dependency-scanning-report.json" ./
    - trivy fs --exit-code 1 --severity HIGH,CRITICAL -o table ./
  cache:
    paths:
      - .trivycache/
  rules:
    - if: $DEPENDENCY_SCANNING_DISABLED
      when: never
    - exists:
        - '{composer.lock,*/composer.lock,*/*/composer.lock}'
        - '{poetry.lock,*/poetry.lock,*/*/poetry.lock}'
        - '{yarn.lock,*/yarn.lock,*/*/yarn.lock}'
        - '{Cargo.lock,*/Cargo.lock,*/*/Cargo.lock}'
        - '{packages.lock.json,*/packages.lock.json,*/*/packages.lock.json}'
        - '{package-lock.json,*/package-lock.json,*/*/package-lock.json}'
        - '{Gemfile.lock,*/Gemfile.lock,*/*/Gemfile.lock}'
        - '{Pipfile.lock,*/Pipfile.lock,*/*/Pipfile.lock}'
        - '{*.jar,*/*.jar,*/*/*.jar}'
        - '{*.war,*/*.war,*/*/*.war}'
        - '{*.ear,*/*.ear,*/*/*.ear}'
      when: always
    - when: never
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
```

It's worth to note that the dependency scanning does currently not produce any 
"remediations" in the output, but it will list any dependencies and detected vulnerabilities.
