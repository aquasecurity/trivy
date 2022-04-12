Thank you for taking interest in contributing to Trivy!

- Feel free to open issues for any reason. When you open a new issue, you'll have to select an issue kind: bug/feature/support and fill the required information based on the selected template.
- Please spend a small amount of time giving due diligence to the issue tracker. Your issue might be a duplicate. If it is, please add your comment to the existing issue.
- Remember that users might search for your issue in the future, so please give it a meaningful title to help others.
- The issue should clearly explain the reason for opening, the proposal if you have any, and any relevant technical information.

## Wrong detection
Trivy depends on Github Advisory Database and Gitlab Advisory Database.
Sometime these databases contain mistakes.

if Trivy can't detect any CVEs or shows false positive result, at first do the next steps:
- run Trivy with `-f json` that shows data sources. Please make sure that data source is correct.
- visit [Github Advisory Database](https://github.com/advisories) and search CVE-ID.
- visit [Gitlab Advisory Database](https://advisories.gitlab.com/) and search CVE-ID .

If the data source is correct and Trivy shows wrong results, please raise an issue on Trivy

If you find a problem, it'll be nice to fix it:
* How to contribute to a GitHub security advisory: https://github.blog/2022-02-22-github-advisory-database-now-open-to-community-contributions/
* Create an issue to Gitlab Advisory Database: https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/issues/new