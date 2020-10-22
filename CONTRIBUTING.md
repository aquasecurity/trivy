Thank you for taking interest in contributing to Trivy !

## Issues
- Feel free to open issues for any reason. When you open a new issue, you'll have to select an issue kind: bug/feature/support and fill the required information based on the selected template.
- Please spend a small amount of time giving due diligence to the issue tracker. Your issue might be a duplicate. If it is, please add your comment to the existing issue.
- Remember users might be searching for your issue in the future, so please give it a meaningful title to help others.
- The issue should clearly explain the reason for opening, the proposal if you have any, and any relevant technical information.

## Pull Requests

1. Every Pull Request should have an associated bug or feature issue unless you are fixing a trivial documentation issue.
1. Your PR is more likely to be accepted if it focuses on just one change.
1. Describe what the PR does. There's no convention enforced, but please try to be concise and descriptive. Treat the PR description as a commit message. Titles that starts with "fix"/"add"/"improve"/"remove" are good examples.
1. Please add the associated Issue in the PR description.
1. There's no need to add or tag reviewers.
1. If a reviewer commented on your code or asked for changes, please remember to mark the discussion as resolved after you address it. PRs with unresolved issues should not be merged (even if the comment is unclear or requires no action from your side).
1. Please include a comment with the results before and after your change.
1. Your PR is more likely to be accepted if it includes tests (We have not historically been very strict about tests, but we would like to improve this!).
1. If your PR affects the user experience in some way, please update the Readme and the CLI help accordingly.

## Understand where your pull request belongs

Trivy is composed of several different repositories that work together:

- [Trivy](https://github.com/aquasecurity/trivy) is the client-side, user-facing, command line tool.
- [vuln-list](https://github.com/aquasecurity/vuln-list) is a vulnerabilities database, aggregated from different sources, and normalized for easy consumption. This of this as the "server" side of the trivy command line tool. **There should be no pull requests to this repo** 
- [vuln-list-update](https://github.com/aquasecurity/vuln-list-update) is the code that maintains the vuln-list database.
- [fanal](https://github.com/aquasecurity/fanal) is a library for extracting system information containers. It is being used by Trivy to find testable subjects in the container image.
