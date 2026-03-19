# Trivy GitHub Actions Workflow Security Audit Report

## Executive Summary
- Total workflows audited: 22
- Total composite actions audited: 2
- Critical findings: 0 (the exploited `apidiff.yaml` was already removed in PR #10259)
- High findings: 2
- Medium findings: 21
- Low findings: 1
- Already fixed upstream (since the March 1 incident): 8+ issues

## Prior Hardening Acknowledgment

The Trivy maintainers have already applied significant security improvements since the March 1 incident:
- Removed the exploited `apidiff.yaml` workflow (PR #10259)
- Removed `roadmap.yaml` workflow
- Fixed multiple script injection vulnerabilities (mkdocs-latest, release, release-please, reusable-release, auto-ready-for-review)
- Replaced `secrets: inherit` with explicit secret declarations in canary.yaml and release.yaml
- Updated composite action `trivy-triage` to SHA-pinned `actions/github-script@v8` with env var for `discussion_num`
- Added `persist-credentials: false` to most checkout steps
- Created a dedicated `setup-go` composite action
- Added `zizmor` GitHub Actions linting to the CI pipeline
- Bumped all actions to latest SHA-pinned versions

This PR addresses the remaining gaps found during a comprehensive audit.

## Methodology
All workflow files in `.github/workflows/` and composite actions in `.github/actions/` were analyzed against five exploitation technique classes modeled on the [hackerbot-claw campaign](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation) that led to the Trivy repository compromise on March 1, 2026:

1. **Pwn Request** — `pull_request_target` combined with untrusted checkout
2. **Script Injection** — `${{ }}` expression interpolation of attacker-controlled values in `run:` blocks
3. **Ungated `issue_comment`** — Privileged operations triggered by comments without authorization checks
4. **Overly Broad Permissions** — Missing or excessive `permissions:` blocks
5. **PAT/Secret Exposure** — Long-lived credentials used where ephemeral tokens suffice, or secrets exposed via command-line arguments

## Workflow Inventory

| File | Trigger(s) | `permissions:` block? | `${{ }}` in `run:`? | Secrets/PATs? | `issue_comment`? | Actions SHA-pinned? |
|------|-----------|---------------------|-------------------|--------------|-----------------|-------------------|
| auto-close-issue.yaml | issues | **No** | No | No | No | Yes |
| auto-ready-for-review.yaml | workflow_run | **No** | Yes | No | No | Yes |
| auto-update-labels.yaml | push | **No** | No | GITHUB_TOKEN | No | Yes |
| backport.yaml | issue_comment | **No** | Yes | GITHUB_TOKEN, ORG_REPO_TOKEN | **Yes** | Yes |
| bypass-cla.yaml | merge_group | **No** | No | No | No | N/A |
| bypass-test.yaml | push, pull_request | **No** | No | No | No | N/A |
| cache-test-assets.yaml | push, workflow_dispatch | **No** | No | No | No | Yes |
| canary.yaml | push, workflow_dispatch | **No** | Yes | Multiple | No | Yes |
| mkdocs-dev.yaml | push | **No** | No | MKDOCS_AQUA_BOT | No | Yes |
| mkdocs-latest.yaml | workflow_dispatch, push | **No** | No | MKDOCS_AQUA_BOT, ORG_REPO_TOKEN | No | Yes |
| publish-chart.yaml | workflow_dispatch, pull_request | **No** | Yes | ORG_REPO_TOKEN | No | Yes |
| release-please.yaml | push, workflow_dispatch | **No** | Yes | ORG_REPO_TOKEN, GITHUB_TOKEN | No | Yes |
| release-pr-check.yaml | pull_request | **No** | No | No | No | N/A |
| release.yaml | push (tags) | **No** | Yes | ORG_REPO_TOKEN, GPG_KEY | No | Yes |
| reusable-release.yaml | workflow_call | Yes | Yes | Multiple | No | Yes |
| scan.yaml | schedule, workflow_dispatch | **No** | No | GITHUB_TOKEN | No | Yes |
| semantic-pr.yaml | pull_request | **No** | No | No | No | N/A |
| spdx-cron.yaml | schedule, workflow_dispatch | **No** | No | TRIVY_MSTEAMS_WEBHOOK | No | Yes |
| stale-issues.yaml | schedule | **No** | No | GITHUB_TOKEN | No | Yes |
| test-docs.yaml | pull_request | **No** | No | No | No | Yes |
| test.yaml | pull_request, merge_group, workflow_dispatch | Partial (zizmor job only) | Yes | No | No | Yes |
| triage.yaml | discussion, workflow_dispatch | **No** | No | No | No | Yes |
| .github/actions/setup-go/action.yaml | (composite) | N/A | No | No | No | Yes |
| .github/actions/trivy-triage/action.yaml | (composite) | N/A | No | github.token | No | Yes |

## Findings

### Finding 1: release.yaml — Secret interpolation in `run:` block
- **File:** .github/workflows/release.yaml
- **Line(s):** 66
- **Vulnerability Class:** Class 5: PAT/Secret Exposure
- **Severity:** High
- **Description:** `${{ secrets.GPG_KEY }}` is interpolated directly with `echo -e` in a `run:` block. The `echo -e` flag interprets escape sequences which could cause partial secret leakage if the key contains special characters. Secrets on the command line can also appear in process listings.
- **Current Code:**
  ```yaml
  run: echo -e "${{ secrets.GPG_KEY }}" | gpg --import
  ```
- **Fix Applied:**
  ```yaml
  env:
    GPG_KEY: ${{ secrets.GPG_KEY }}
  run: echo -e "$GPG_KEY" | gpg --import
  ```

### Finding 2: publish-chart.yaml — Secret on command line
- **File:** .github/workflows/publish-chart.yaml
- **Line(s):** 84
- **Vulnerability Class:** Class 5: PAT/Secret Exposure
- **Severity:** High
- **Description:** `secrets.ORG_REPO_TOKEN` is interpolated directly as `--token ${{ secrets.ORG_REPO_TOKEN }}` in a `run:` block. While GitHub redacts known secrets from logs, secrets on the command line can appear in process listings (`/proc/*/cmdline`) and may leak in error messages.
- **Current Code:**
  ```yaml
  run: |
    ./cr upload -o ${{ env.GH_OWNER }} -r ${{ env.HELM_REP }} --token ${{ secrets.ORG_REPO_TOKEN }} -p .cr-release-packages
  ```
- **Fix Applied:**
  ```yaml
  env:
    CR_TOKEN: ${{ secrets.ORG_REPO_TOKEN }}
  run: |
    ./cr upload -o "$GH_OWNER" -r "$HELM_REP" --token "$CR_TOKEN" -p .cr-release-packages
  ```

### Finding 3: release-please.yaml — Secret on command line
- **File:** .github/workflows/release-please.yaml
- **Line(s):** 39
- **Vulnerability Class:** Class 5: PAT/Secret Exposure
- **Severity:** Medium
- **Description:** `secrets.ORG_REPO_TOKEN` is interpolated directly as `--token="${{ secrets.ORG_REPO_TOKEN }}"` on the command line. While most other interpolations in this file were already fixed upstream via `$GITHUB_*` env vars, the token is still directly interpolated.
- **Fix Applied:**
  ```yaml
  env:
    RP_TOKEN: ${{ secrets.ORG_REPO_TOKEN }}
  run: |
    release-please release-pr ... --token="$RP_TOKEN" ...
  ```

### Finding 4: test.yaml — `${{ matrix.operating-system }}` in `run:` block
- **File:** .github/workflows/test.yaml
- **Line(s):** 248-254
- **Vulnerability Class:** Class 2: Script Injection
- **Severity:** Low (hardcoded matrix values, not exploitable)
- **Description:** Matrix values are hardcoded in the workflow file (`ubuntu-latest`, `windows-latest`, `macos-latest`), so this is not exploitable. Fixed for consistency with best practices and to satisfy `zizmor` linting.
- **Fix Applied:** Moved to `env: OPERATING_SYSTEM` variable.

### Finding 5: publish-chart.yaml — ORG_REPO_TOKEN passed to third-party action
- **File:** .github/workflows/publish-chart.yaml
- **Line(s):** 89-98
- **Vulnerability Class:** Class 5: PAT/Secret Exposure
- **Severity:** Medium
- **Description:** `secrets.ORG_REPO_TOKEN` is passed as `API_TOKEN_GITHUB` to `dmnemec/copy_file_to_another_repo_action@c93037aa10fa8893de271f19978c980d0c1a9b37`. While SHA-pinned, this is a lesser-known third-party action receiving an org-scoped PAT with cross-repo write access. The action has low star count and limited maintainer scrutiny compared to official GitHub Actions.
- **Recommended Fix:** **Requires maintainer input.** Consider replacing with `gh` CLI or a GitHub App token for cross-repo index file publishing.
- **Status:** Not fixed — flagged for maintainer review.

### Finding 6: mkdocs-dev.yaml and mkdocs-latest.yaml — Token in pip install URL
- **File:** .github/workflows/mkdocs-dev.yaml (line 25), .github/workflows/mkdocs-latest.yaml (line 27)
- **Vulnerability Class:** Class 5: PAT/Secret Exposure
- **Severity:** Medium
- **Description:** `secrets.MKDOCS_AQUA_BOT` is embedded in a `pip install git+https://${GH_TOKEN}@github.com/...` URL. While the token is correctly passed via `env:` (not direct `${{ }}` interpolation), the pip URL pattern is a known anti-pattern — pip may log the full URL on errors, exposing the token in workflow logs.
- **Recommended Fix:** **Requires maintainer input.** Consider using `git config url."https://${GH_TOKEN}@github.com/".insteadOf "https://github.com/"` before `pip install`.
- **Status:** Not fixed — flagged for maintainer review.

### Findings 7-26: Missing `permissions:` blocks (20 workflows)
- **Vulnerability Class:** Class 4: Overly Broad Token Permissions
- **Severity:** Medium
- **Description:** 20 out of 22 workflows lack explicit `permissions:` blocks, inheriting the repository default which may grant overly broad access. Only `reusable-release.yaml` has a workflow-level permissions block; `test.yaml` has one on the `zizmor` job only.
- **Status:** Fixed — all 20 workflows now have explicit `permissions:` blocks with minimum required scopes.

| Workflow | Permissions Added |
|----------|------------------|
| auto-close-issue.yaml | `issues: write` |
| auto-ready-for-review.yaml | `actions: read`, `pull-requests: write` |
| auto-update-labels.yaml | `contents: read`, `issues: write` |
| backport.yaml | `contents: write`, `pull-requests: write`, `issues: read` |
| bypass-cla.yaml | `{}` (none) |
| bypass-test.yaml | `{}` (none) |
| cache-test-assets.yaml | `contents: read` |
| canary.yaml | `contents: read`, `packages: write`, `id-token: write`, `actions: write`, `attestations: write` |
| mkdocs-dev.yaml | `contents: write` |
| mkdocs-latest.yaml | `contents: write` |
| publish-chart.yaml | `contents: read` |
| release-please.yaml | `contents: write`, `pull-requests: write` |
| release-pr-check.yaml | `contents: read` |
| release.yaml | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` |
| scan.yaml | `contents: read`, `issues: write` |
| semantic-pr.yaml | `contents: read` |
| spdx-cron.yaml | `contents: read` |
| stale-issues.yaml | `issues: write`, `pull-requests: write` |
| test-docs.yaml | `contents: read` |
| test.yaml | `contents: read` |
| triage.yaml | `contents: read`, `discussions: write` |

## No-Issue Confirmations

The following workflows/actions were reviewed and found to have no remaining issues:

- **reusable-release.yaml** — Has explicit permissions. GPG key handled via env var. Actions SHA-pinned. `persist-credentials: false`.
- **setup-go composite action** — Clean implementation. Input passed via env var. Action SHA-pinned.
- **trivy-triage composite action** — Already fixed upstream: `discussion_num` via `process.env`, github-script SHA-pinned.
- **bypass-cla.yaml** / **bypass-test.yaml** — No-op echo workflows. No security concerns.
- **cache-test-assets.yaml** — Push to main only, all actions SHA-pinned. No injection vectors.
- **semantic-pr.yaml** — PR title correctly passed via `env:` variable (safe pattern).
- **release-pr-check.yaml** — PR author login correctly passed via `env:` variable.
- **test-docs.yaml** — Uses `pull_request` (not `pull_request_target`). No secret access for forks.
- **backport.yaml** — Uses `issue_comment` with proper authorization gate (`check_permission` job verifies admin/write access). Comment body passed via `env:` variable with regex validation.
- **auto-ready-for-review.yaml** — Already fixed upstream: PR number via `process.env`. Zizmor annotation for `workflow_run` trigger.
- **mkdocs-latest.yaml** — Already fixed upstream: all `${{ }}` expressions moved to env vars/`$GITHUB_*`.
- **release.yaml** — Already fixed upstream: `$GITHUB_REPOSITORY_OWNER` and `$GITHUB_REF_NAME` used throughout.

## Recommendations

### Priority 1 (Address in this PR)
1. ~~Move `secrets.GPG_KEY` to env var in release.yaml~~ **Done**
2. ~~Move `secrets.ORG_REPO_TOKEN` off command line in publish-chart.yaml and release-please.yaml~~ **Done**
3. ~~Add `permissions:` blocks to all 20 workflows~~ **Done**
4. ~~Move `matrix.operating-system` to env var in test.yaml~~ **Done**

### Priority 2 (Maintainer review needed)
5. Replace `dmnemec/copy_file_to_another_repo_action` with `gh` CLI in publish-chart.yaml — eliminates third-party action receiving org PAT
6. Fix pip URL token pattern in mkdocs workflows — use `git config url` rewriting
7. Audit `ORG_REPO_TOKEN` scope — ensure it has minimum required permissions

### Priority 3 (General hardening)
8. Set repository-level default permissions to `read` in Settings > Actions > General > Workflow permissions (makes the `permissions:` blocks added here redundant as defense-in-depth)
9. Consider replacing `ORG_REPO_TOKEN` (classic PAT) with GitHub App tokens for cross-repo operations (auto-expiring, more auditable, granular scopes)
