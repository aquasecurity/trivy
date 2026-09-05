# Trivy workflow examples for GitLab CI

This directory complements `examples/workflows` by showing how the same scanning lanes can be wired into GitLab CI.

Included jobs in `Trivy.gitlab-ci.workflows.yml`:

- `trivy_fs_and_secret`: local repository / filesystem dependency and secret scanning
- `trivy_iac`: misconfiguration and IaC scanning
- `trivy_image_release`: release-image scanning using `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA`
- `trivy_repo_vex`: scheduled or manual repository rescans with `--vex repo`
- `trivy_sbom`: SBOM rescanning from `sbom.cdx.json`
- `trivy_k8s`: Kubernetes cluster scanning from `$KUBECONFIG_CONTENT`

Usage:

```yaml
include:
  - local: contrib/workflows/Trivy.gitlab-ci.workflows.yml
```

Then set any required CI variables for image registry auth or kubeconfig content in your GitLab project settings.
