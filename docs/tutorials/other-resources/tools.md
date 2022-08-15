# Community Tools
The open source community has been hard at work developing new tools for Trivy. You can check out some of them here.

Have you created a tool that’s not listed? Add the name and description of your integration and open a pull request in the GitHub repository to get your change merged.

## GitHub Actions

| Actions                                    | Description                                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------------- |
| [gitrivy][gitrivy]                         | GitHub Issue + Trivy                                                             |
| [trivy-github-issues][trivy-github-issues] | GitHub Actions for creating GitHub Issues according to the Trivy scanning result |

## Semaphore

| Name                                                   | Description                               |
| -------------------------------------------------------| ----------------------------------------- |
| [Continuous Vulnerability Testing with Trivy][semaphore-tutorial] | Tutorial on scanning code, containers, infrastructure, and Kubernetes with Semaphore CI/CD. |


## CircleCI

| Orb                                      | Description                               |
| -----------------------------------------| ----------------------------------------- |
| [fifteen5/trivy-orb][fifteen5/trivy-orb] | Orb for running Trivy, a security scanner |


## Trivy VSCode

| Orb                | Description                 |
| ------------------ | --------------------------- |
| [vs-code][vs-code] | VS Code extension for trivy |


## Vim Trivy

| Orb                    | Description             |
| ---------------------- | ----------------------- |
| [vim-trivy][vim-trivy] | Vim extension for trivy |


## Trivy Docker Desktop

| Orb                              | Description                                                                                           |
| ---------------------------------| ----------------------------------------------------------------------------------------------------- |
| [docker-desktop][docker-desktop] | Trivy Docker Desktop extension for scanning container images for vulnerabilities and generating SBOMs |


## Trivy Azure DevOps

| Orb                          | Description                                                      |
| ---------------------------- | ---------------------------------------------------------------- |
| [azure-devops][azure-devops] | An Azure DevOps Pipelines Task for Trivy, with an integrated UI. |


## Trivy Operator

| Orb                              | Description                              |
| ---------------------------------| ---------------------------------------- |
| [trivy-operator][trivy-operator] | Kubernetes Operator for installing Trivy |


## Trivy Kubernetes Lens Extension

| Orb                          | Description                         |
| ---------------------------- | ----------------------------------- |
| [lens-extension][trivy-lens] | Trivy Extension for Kubernetes Lens |


## Others

| Name                                     | Description                               |
| -----------------------------------------| ----------------------------------------- |
| [Trivy Vulnerability Explorer][explorer] | Explore trivy vulnerability reports in your browser and create .trivyignore files interactively. Can be integrated in your CI/CD tooling with deep links.   |


[trivy-github-issues]: https://github.com/marketplace/actions/trivy-github-issues
[fifteen5/trivy-orb]: https://circleci.com/developer/orbs/orb/fifteen5/trivy-orb
[gitrivy]: https://github.com/marketplace/actions/trivy-action
[explorer]: https://dbsystel.github.io/trivy-vulnerability-explorer/
[semaphore-tutorial]: https://semaphoreci.com/blog/continuous-container-vulnerability-testing-with-trivy
[vs-code]: https://github.com/aquasecurity/trivy-vscode-extension
[vim-trivy]: https://github.com/aquasecurity/vim-trivy
[docker-desktop]: https://github.com/aquasecurity/trivy-docker-extension
[azure-devops]: https://github.com/aquasecurity/trivy-azure-pipelines-task
[trivy-operator]: https://github.com/aquasecurity/trivy-operator
[trivy-lens]: https://github.com/aquasecurity/trivy-operator-lens-extension
