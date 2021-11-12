# Community Tools
The open source community has been hard at work developing new tools for Trivy. You can check out some of them here.

Have you created a tool that’s not listed? Add the name and description of your integration and open a pull request in the GitHub repository to get your change merged.

## GitHub Actions

| Actions                                    | Description                                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------------- |
| [gitrivy][gitrivy]                         | GitHub Issue + Trivy                                                             |
| [trivy-github-issues][trivy-github-issues] | GitHub Actions for creating GitHub Issues according to the Trivy scanning result |

## CircleCI

| Orb                                      | Description                               |
| -----------------------------------------| ----------------------------------------- |
| [fifteen5/trivy-orb][fifteen5/trivy-orb] | Orb for running Trivy, a security scanner |

## Others

| Name                                     | Description                               |
| -----------------------------------------| ----------------------------------------- |
| [Trivy Vulnerability Explorer][explorer] | Explore trivy vulnerability reports in your browser and create .trivyignore files interactively. Can be integrated in your CI/CD tooling with deep links.   |


[trivy-github-issues]: https://github.com/marketplace/actions/trivy-github-issues
[fifteen5/trivy-orb]: https://circleci.com/developer/orbs/orb/fifteen5/trivy-orb
[gitrivy]: https://github.com/marketplace/actions/trivy-action
[explorer]: https://dbsystel.github.io/trivy-vulnerability-explorer/