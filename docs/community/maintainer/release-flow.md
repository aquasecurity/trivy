# Release Flow

## Overview
Trivy adopts [conventional commit messages][conventional-commits], and [Release Please][release-please] automatically creates a [release PR](https://github.com/googleapis/release-please?tab=readme-ov-file#whats-a-release-pr) based on the messages of the merged commits.
This release PR is automatically updated every time a new commit is added to the release branch.

If a commit has the prefix `feat:`, a PR is automatically created to increment the minor version, and if a commit has the prefix `fix:`, a PR is created to increment the patch version.
When the PR is merged, GitHub Actions automatically creates a version tag and the release is performed.
For detailed behavior, please refer to [the GitHub Actions configuration][workflows].

!!! note
    Commits with prefixes like `chore` or `build` are not considered releasable, and no release PR is created.
    To include such commits in a release, you need to either include commits with `feat` or `fix` prefixes or perform a manual release as described [below](#manual-release-pr-creation).

## Flow
The release flow consists of the following main steps:

1. Creating the release PR (automatically or manually)
1. Drafting the release notes in GitHub Discussions
1. Merging the release PR
1. Updating the release notes in GitHub Discussions
1. Navigating to the release notes in GitHub Releases page

### Automatic Release PR Creation
When a releasable commit (a commit with `feat` or `fix` prefix) is merged, a release PR is automatically created.
These Release PRs are kept up-to-date as additional work is merged.
When it's ready to tag a release, simply merge the release PR.
See the [Release Please documentation][release-please] for more information.

The title of the PR will be in the format `release: v${version} [${branch}]` (e.g., `release: v0.51.0 [main]`).
The format of the PR title is important for identifying the release commit, so it should not be changed.

The `release/vX.Y` release branches are also subject to automatic release PR creation for patch releases.
The PR title will be like `release: v0.51.1 [release/v0.51]`.

### Manual Release PR Creation
If you want to release commits like `chore`, a release PR is not automatically created, so you need to manually trigger the creation of a release PR.
The [Release Please workflow](https://github.com/aquasecurity/trivy/actions/workflows/release-please.yaml) supports `workflow_dispatch` and can be triggered manually.
Click "Run workflow" in the top right corner and specify the release branch.
In Trivy, the following branches are the release branches.

- `main`
- `release/vX.Y` (e.g. `release/v0.51`)

Specify the release version (without the `v` prefix) and click "Run workflow" to create a release PR for the specified version.

### Drafting the Release Notes
Next, create release notes for this version.
Draft a new post in GitHub Discussions, and maintainers edit these release notes (e.g., https://github.com/aquasecurity/trivy/discussions/6605).
Currently, the creation of this draft is done manually.
For patch version updates, this step can be skipped since they only involve bug fixes.

### Merging the Release PR
Once the draft of the release notes is complete, merge the release PR.
When the PR is merged, a tag is automatically created, and [GoReleaser][goreleaser] releases binaries, container images, etc.

### Updating the Release Notes
If the release completes without errors, a page for the release notes is created in GitHub Discussions (e.g., https://github.com/aquasecurity/trivy/discussions/6622).
Copy the draft release notes, adjust the formatting, and finalize the release notes.

### Navigating to the Release Notes
To navigate to the release highlights and summary in GitHub Discussions, place a link in the GitHub Releases page as below:

```
## ⚡Release highlights and summary⚡

👉 https://github.com/aquasecurity/trivy/discussions/6838

## Changelog
https://github.com/aquasecurity/trivy/blob/main/CHANGELOG.md#0520-2024-06-03
```

Replace URLs with appropriate ones.

Example: https://github.com/aquasecurity/trivy/releases/tag/v0.52.0


The release is now complete.

[conventional-commits]: https://www.conventionalcommits.org/en/v1.0.0/
[release-please]: https://github.com/googleapis/release-please 
[goreleaser]: https://goreleaser.com/
[workflows]: https://github.com/aquasecurity/trivy/tree/main/.github/workflows