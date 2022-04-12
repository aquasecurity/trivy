Thank you for taking interest in contributing to Trivy!

- Feel free to open issues for any reason. When you open a new issue, you'll have to select an issue kind: bug/feature/support and fill the required information based on the selected template.
- Please spend a small amount of time giving due diligence to the issue tracker. Your issue might be a duplicate. If it is, please add your comment to the existing issue.
- Remember that users might search for your issue in the future, so please give it a meaningful title to help others.
- The issue should clearly explain the reason for opening, the proposal if you have any, and any relevant technical information.

## Wrong detection
Trivy depends on [multiple data sources](https://aquasecurity.github.io/trivy/latest/docs/vulnerability/detection/data-source/).
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

