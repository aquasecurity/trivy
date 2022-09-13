# Azure Devops

- Here is the [Azure DevOps Pipelines Task for Trivy][action]

![trivy-azure](https://github.com/aquasecurity/trivy-azure-pipelines-task/blob/main/screenshot.png?raw=true)

### [Microsoft Defender for container registries and Trivy][azure]

This blog explains how to scan your Azure Container Registry-based container images with the integrated vulnerability scanner when they're built as part of your GitHub workflows.

To set up the scanner, you'll need to enable Microsoft Defender for Containers and the CI/CD integration. When your CI/CD workflows push images to your registries, you can view registry scan results and a summary of CI/CD scan results.

The findings of the CI/CD scans are an enrichment to the existing registry scan findings by Qualys. Defender for Cloud's CI/CD scanning is powered by Aqua Trivy

[action]: https://github.com/aquasecurity/trivy-azure-pipelines-task
[azure]: https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-cicd
