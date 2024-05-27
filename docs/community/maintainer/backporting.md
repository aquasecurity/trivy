# Backporting Process

This document outlines the backporting process for Trivy, including when to create patch releases and how to perform the backporting.

## When to Create Patch Releases

In general, small changes should not be backported and should be included in the next minor release.
However, patch releases should be made in the following cases:

* Fixes for HIGH or CRITICAL vulnerabilities in Trivy itself or Trivy's dependencies
* Fixes for bugs that cause panic during Trivy execution or otherwise interfere with normal usage

In these cases, the fixes should be backported using the procedure [described below](#backporting-procedure).
At the maintainer's discretion, other bug fixes may be included in the patch release containing these hotfixes.

## Versioning

Trivy follows [Semantic Versioning](https://semver.org/), using version numbers in the format MAJOR.MINOR.PATCH.
When creating a patch release, the PATCH part of the version number is incremented.
For example, if a fix is being distributed for v0.50.0, the patch release would be v0.50.1.

## Backporting Procedure

1. Create a release branch (e.g., `release/v0.50`) from the main branch.
1. Create a pull request against the main branch with the necessary fixes. If the fixes are already merged into the main branch, skip this step.
1. Once the pull request with the fixes is merged, label the pull request with the `backport-to-<release-branch>` label (e.g., `backport-to-release/v0.50`). This will trigger the automated backporting process using GitHub Actions.
1. The automated process will create a new pull request with the backported changes. Ensure that all tests pass for this pull request.
1. Once the tests pass, merge the automatically created pull request into the release branch.
1. Create a new release tag (e.g., `v0.50.1`) on the release branch and publish the release.

### Example
To better understand the backporting procedure, let's walk through an example using the releases of v0.43.

```mermaid
gitGraph:
  commit id:"Feature 1"
  commit id:"v0.50.0 release" tag:"v0.50.0"

  branch "release/v0.50"
  
  checkout main
  commit id:"Bugfix 1"

  checkout "release/v0.50"
  cherry-pick id:"Bugfix 1"

  checkout main
  commit id:"Feature 2"
  commit id:"Bugfix 2"
  commit id:"Feature 3"

  checkout "release/v0.50"
  cherry-pick id:"Bugfix 2"
  commit id:"v0.50.1 release" tag:"v0.50.1"
```