# CI/CD Integrations

## Azure DevOps (Official)
[Azure Devops](https://azure.microsoft.com/en-us/products/devops/#overview) is Microsoft Azure cloud native CI/CD service.

Trivy has a "Azure Devops Pipelines Task" for Trivy, that lets you easily introduce security scanning into your workflow, with an integrated Azure Devops UI.

👉 Get it at: <https://github.com/aquasecurity/trivy-azure-pipelines-task>

## GitHub Actions
[GitHub Actions](https://github.com/features/actions) is GitHub's native CI/CD and job orchestration service.

### trivy-action (Official)

GitHub Action for integrating Trivy into your GitHub pipeline

👉 Get it at: <https://github.com/aquasecurity/trivy-action>

### trivy-action (Community)

GitHub Action to scan vulnerability using Trivy. If vulnerabilities are found by Trivy, it creates a GitHub Issue.

👉 Get it at: <https://github.com/marketplace/actions/trivy-action>

### trivy-github-issues (Community)

In this action, Trivy scans the dependency files such as package-lock.json and go.sum in your repository, then create GitHub issues according to the result.

👉 Get it at: <https://github.com/marketplace/actions/trivy-github-issues>

## Buildkite Plugin (Community)

The trivy buildkite plugin provides a convenient mechanism for running the open-source trivy static analysis tool on your project. 

👉 Get it at: https://github.com/equinixmetal-buildkite/trivy-buildkite-plugin

## Dagger (Community)
[Dagger](https://dagger.io/) is CI/CD as code that runs anywhere.

The Dagger module for Trivy provides functions for scanning container images from registries as well as Dagger Container objects from any Dagger SDK (e.g. Go, Python, Node.js, etc).

👉 Get it at: <https://daggerverse.dev/mod/github.com/jpadams/daggerverse/trivy>


## Semaphore (Community)
[Semaphore](https://semaphore.io/) is a CI/CD service.

You can use Trivy in Semaphore for scanning code, containers, infrastructure, and Kubernetes in Semaphore workflow.

👉 Get it at: <https://docs.semaphore.io/using-semaphore/recipes/trivy>

## CircleCI (Community)
[CircleCI](https://circleci.com/) is a CI/CD service.

You can use the Trivy Orb for Circle CI to introduce security scanning into your workflow.

👉 Get it at: <https://circleci.com/developer/orbs/orb/fifteen5/trivy-orb>
Source: <https://github.com/15five/trivy-orb>

## Woodpecker CI (Community)

Example Trivy step in pipeline

```yml
pipeline:
  securitycheck:
    image: aquasec/trivy:latest
    commands:
      # use any trivy command, if exit code is 0 woodpecker marks it as passed, else it assumes it failed
      - trivy fs --exit-code 1 --skip-dirs web/ --skip-dirs docs/ --severity MEDIUM,HIGH,CRITICAL .
```

Woodpecker does use Trivy itself so you can [see it in use there](https://github.com/woodpecker-ci/woodpecker/pull/1163).

## Concourse CI (Community)
[Concourse CI](https://concourse-ci.org/) is a CI/CD service.

You can use Trivy Resource in Concourse for scanning containers and introducing security scanning into your workflow.
It has capabilities to fail the pipeline, create issues, alert communication channels (using respective resources) based on Trivy scan output.

👉 Get it at: <https://github.com/Comcast/trivy-resource/>


## SecObserve GitHub actions and GitLab templates (Community)
[SecObserve GitHub actions and GitLab templates](https://github.com/MaibornWolff/secobserve_actions_templates) run various vulnerability scanners, providing uniform methods and parameters for launching the tools.

The Trivy integration supports scanning Docker images and local filesystems for vulnerabilities as well as scanning IaC files for misconfigurations.

👉 Get it at: <https://github.com/MaibornWolff/secobserve_actions_templates>
