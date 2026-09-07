# Workflow examples

This page collects concrete, copy-pasteable workflow examples for common Trivy operating modes. The files live under [`examples/workflows`](../../../examples/workflows), [`contrib/workflows`](../../../contrib/workflows), and selected live workflows under [`.github/workflows`](../../../.github/workflows) in this repository.

## Included examples

### Shared local files

- [`examples/workflows/trivy.yaml`](../../../examples/workflows/trivy.yaml): shared baseline config for filesystem and repository scans.
- [`examples/workflows/.trivyignore`](../../../examples/workflows/.trivyignore): example ignore file for findings your team has explicitly accepted.
- [`examples/workflows/.pre-commit-config.yaml`](../../../examples/workflows/.pre-commit-config.yaml): local developer workflow using `trivy fs` and `trivy config` before code reaches CI.

### GitHub Actions examples

- [`examples/workflows/github-actions/repo-and-iac-pr.yml`](../../../examples/workflows/github-actions/repo-and-iac-pr.yml): reusable PR workflow example for dependency, secret, and IaC scanning.
- [`examples/workflows/github-actions/image-release.yml`](../../../examples/workflows/github-actions/image-release.yml): reusable release-image gate with JSON and CycloneDX outputs.
- [`examples/workflows/github-actions/repository-vex-scheduled.yml`](../../../examples/workflows/github-actions/repository-vex-scheduled.yml): reusable scheduled repository scan with `--vex repo` and SARIF conversion.
- [`examples/workflows/github-actions/sbom-audit.yml`](../../../examples/workflows/github-actions/sbom-audit.yml): reusable SBOM rescanning workflow for existing CycloneDX or SPDX inventories.
- [`examples/workflows/github-actions/kubernetes-cluster.yml`](../../../examples/workflows/github-actions/kubernetes-cluster.yml): reusable scheduled or on-demand Kubernetes cluster scan.

### Live GitHub workflows added in this repository

- [`.github/workflows/repo-and-iac-pr.yaml`](../../../.github/workflows/repo-and-iac-pr.yaml): active PR and manual scan workflow for this repository.
- [`.github/workflows/image-release.yaml`](../../../.github/workflows/image-release.yaml): active scheduled/manual image scan against `ghcr.io/aquasecurity/trivy:latest` by default.
- [`.github/workflows/repository-vex-scheduled.yaml`](../../../.github/workflows/repository-vex-scheduled.yaml): active scheduled/manual repository rescan with VEX enabled.
- [`.github/workflows/sbom-audit.yaml`](../../../.github/workflows/sbom-audit.yaml): active scheduled/manual SBOM rescan workflow.
- [`.github/workflows/kubernetes-cluster.yaml`](../../../.github/workflows/kubernetes-cluster.yaml): active scheduled/manual Kubernetes cluster workflow.

### GitLab CI examples

- [`contrib/workflows/Trivy.gitlab-ci.workflows.yml`](../../../contrib/workflows/Trivy.gitlab-ci.workflows.yml): GitLab CI bundle covering filesystem, IaC, image, repository+VEX, SBOM, and Kubernetes jobs.
- [`contrib/workflows/README.md`](../../../contrib/workflows/README.md): quick usage notes for the GitLab workflow bundle.

## Mapping from workflow to Trivy commands

### Local developer checks

Use `.pre-commit-config.yaml` when you want developers to catch obvious dependency, secret, and IaC issues before opening a pull request.

Core commands:

```bash
trivy fs --config examples/workflows/trivy.yaml --ignorefile examples/workflows/.trivyignore --scanners vuln,secret .
trivy config --severity HIGH,CRITICAL --exit-code 1 .
```

### Pull request repository and IaC scanning

Use `repo-and-iac-pr.yml` or `.github/workflows/repo-and-iac-pr.yaml` when you want a fast PR gate that checks the working tree directly.

Core commands:

```bash
trivy fs --config examples/workflows/trivy.yaml --ignorefile examples/workflows/.trivyignore --scanners vuln,secret --format sarif --output trivy-fs.sarif .
trivy config --severity HIGH,CRITICAL --format sarif --output trivy-config.sarif .
```

### Release image scanning

Use `image-release.yml`, `.github/workflows/image-release.yaml`, or the GitLab `trivy_image_release` job after building and publishing an image.

Core commands:

```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed --format json --output trivy-image.json "$IMAGE_REF"
trivy image --severity HIGH,CRITICAL --ignore-unfixed --format cyclonedx --output trivy-image.cdx.json "$IMAGE_REF"
```

### Scheduled repository scanning with VEX

Use `repository-vex-scheduled.yml`, `.github/workflows/repository-vex-scheduled.yaml`, or the GitLab `trivy_repo_vex` job for nightly or daily rescans of a Git URL.

Core commands:

```bash
trivy repo --config examples/workflows/trivy.yaml --ignorefile examples/workflows/.trivyignore --scanners vuln,misconfig,secret,license --severity HIGH,CRITICAL --vex repo --format json --output trivy-repo.json "$REPOSITORY_URL"
trivy convert --format sarif --output trivy-repo.sarif trivy-repo.json
```

### SBOM rescanning

Use `sbom-audit.yml`, `.github/workflows/sbom-audit.yaml`, or the GitLab `trivy_sbom` job when another stage already produced a CycloneDX or SPDX SBOM.

Core commands:

```bash
trivy sbom --scanners vuln,license --severity HIGH,CRITICAL --format json --output trivy-sbom.json "$SBOM_PATH"
trivy convert --format sarif --output trivy-sbom.sarif trivy-sbom.json
```

### Kubernetes cluster checks

Use `kubernetes-cluster.yml`, `.github/workflows/kubernetes-cluster.yaml`, or the GitLab `trivy_k8s` job for scheduled cluster posture or workload checks.

Core commands:

```bash
trivy k8s --kubeconfig ~/.kube/config --report summary --severity HIGH,CRITICAL --format json --output trivy-k8s.json cluster
trivy k8s --kubeconfig ~/.kube/config --report summary --severity HIGH,CRITICAL --include-namespaces "$NAMESPACE" cluster
```

## Repo-specific tightening applied here

- Live GitHub workflows are pinned to immutable action SHAs to match this repository's existing workflow style.
- Live GitHub workflows use `ubuntu-2404-2core`, matching the runner used by existing workflows in this repository.
- Live GitHub workflows install Trivy through `./contrib/install.sh` from the checked-out repository instead of fetching a remote script path directly.
- The default repository/image references in the live workflows point at this project (`https://github.com/aquasecurity/trivy` and `ghcr.io/aquasecurity/trivy:latest`).

## Notes

- The example workflows stay reusable, while the live GitHub workflows are tightened to this repository's conventions.
- The examples upload generated artifacts rather than wiring to a specific external reporting backend.
- Replace accepted ignores, kubeconfig secret handling, and SBOM paths with values appropriate for your environment.
