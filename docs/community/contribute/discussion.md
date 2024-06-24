# Discussions
Thank you for taking interest in contributing to Trivy!

Trivy uses [GitHub Discussion](https://github.com/aquasecurity/trivy/discussions) for bug reports, feature requests, and questions.
If maintainers decide to accept a new feature or confirm that it is a bug, they will close the discussion and create a [GitHub Issue](https://github.com/aquasecurity/trivy/issues) associated with that discussion.

- Feel free to open discussions for any reason. When you open a new discussion, you'll have to select a discussion category as described below.
- Please spend a small amount of time giving due diligence to the issue/discussion tracker. Your discussion might be a duplicate. If it is, please add your comment to the existing issue/discussion.
- Remember that users might search for your issue/discussion in the future, so please give it a meaningful title to help others.
- The issue should clearly explain the reason for opening, the proposal if you have any, and any relevant technical information.

There are 4 categories:

- 💡 [Ideas](https://github.com/aquasecurity/trivy/discussions/categories/ideas)
    - Share ideas for new features
- 🔎 [False Detection](https://github.com/aquasecurity/trivy/discussions/categories/false-detection)
    - Report false positives/negatives
- 🐛 [Bugs](https://github.com/aquasecurity/trivy/discussions/categories/bugs)
    - Report something that is not working as expected
- 🙏 [Q&A](https://github.com/aquasecurity/trivy/discussions/categories/q-a)
    - Ask the community for help

!!! note
    If you find any false positives or false negatives, please make sure to report them under the "False Detection" category, not "Bugs".

## False detection
Trivy depends on [multiple data sources](https://aquasecurity.github.io/trivy/latest/docs/scanner/vulnerability/#data-sources).
Sometime these databases contain mistakes.

If Trivy can't detect any CVE-IDs or shows false positive result, at first please follow the next steps:

1. Run Trivy with `-f json` that shows data sources.
2. According to the shown data source, make sure that the security advisory in the data source is correct.

If the data source is correct and Trivy shows wrong results, please raise an issue on Trivy.

### GitHub Advisory Database
Visit [here](https://github.com/advisories) and search CVE-ID.

If you find a problem, it'll be nice to fix it: [How to contribute to a GitHub security advisory](https://github.blog/2022-02-22-github-advisory-database-now-open-to-community-contributions/)
 
### GitLab Advisory Database
Visit [here](https://advisories.gitlab.com/) and search CVE-ID.

If you find a problem, it'll be nice to fix it: [Create an issue to GitLab Advisory Database](https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/issues/new)
 
### Red Hat CVE Database
Visit [here](https://access.redhat.com/security/security-updates/?cwe=476#/cve) and search CVE-ID.

