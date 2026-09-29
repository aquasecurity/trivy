# Pull Request Review Policy

This document outlines the review policy for pull requests in the Trivy project.

## Core Principles

### 1. All Changes Through Pull Requests
All changes to the `main` branch must be made through pull requests.
Direct commits to `main` are not allowed.

### 2. Required Approvals
Every pull request requires approval from at least one CODEOWNER before merging.

For changes that span multiple domains (e.g., both vulnerability and misconfiguration scanning), approval from at least one code owner from each affected domain is required.

When a pull request is created by the only code owner of a domain, approval from any other maintainer is required.

When a code owner wants additional input from other owners or maintainers, they should comment requesting feedback and wait for others to approve before providing their own approval.
This prevents accidental merging by the PR author.

### 3. Merge Responsibility
- **General Rule**: The pull request author should click the merge button after receiving required approvals
- **Exception**: For urgent fixes (hotfixes), a CODEOWNER may merge the PR directly
- **External Contributors**: Pull requests from external contributors should be merged by a CODEOWNER