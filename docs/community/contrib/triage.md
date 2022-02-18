Triage is an important part of maintaining the health of the trivy repo.
A well organized repo allows maintainers to prioritize feature requests, fix bugs, and respond to users facing difficulty with the tool as quickly as possible.

Triage includes:
- Labeling issues
- Responding to issues
- Closing issues

# Daily Triage
Daily triage has two goals:

1. Responsiveness for new issues
1. Responsiveness when explicitly requested information was provided

It covers:

1. Issues without a `kind/` or `triage/` label
1. Issues without a `priority/` label
1. `triage/needs-information` issues which the user has followed up on, and now require a response.

## Categorization

The most important level of categorizing the issue is defining what type it is.
We typically want at least one of the following labels on every issue, and some issues may fall into multiple categories:

- `triage/support`   - The default for most incoming issues
- `kind/bug` - When it’s a bug or we aren’t delivering the best user experience

Other possibilities: 
- `kind/feature`- Identify new feature requests
- `kind/testing` - Update or fix unit/integration tests
- `kind/cleanup` - Cleaning up/refactoring the codebase
- `kind/documentation` - Updates or additions to trivy documentation

If the issue is specific to a driver for OS packages or libraries:

**co/[driver for OS packages]**

  - `co/alpine`
  - `co/amazon`
  - `co/debian`
  - `co/oracle`
  - `co/photon`
  - `co/redhat`
  - `co/suse`
  - `co/ubuntu`

**co/[driver for libraries of programming languages]** 

  - `co/bundler`
  - `co/cargo`
  - `co/composer`
  - `co/npm`
  - `co/yarn`
  - `co/pipenv`
  - `co/poetry`
 

**Help wanted?**

`Good First Issue` - bug has a proposed solution, can be implemented w/o further discussion.

`Help wanted` - if the bug could use help from a contributor


## Prioritization
If the issue is not `triage/support`, it needs a priority label.

`priority/critical-urgent` - someones top priority ASAP, such as security issue, user-visible bug, or build breakage. Rarely used.

`priority/important-soon`: in time for the next two releases. It should be attached to a milestone.

`priority/important-longterm`: 2-4 releases from now

`priority/backlog`: agreed that this would be good to have, but no one is available at the moment. Consider tagging as `help wanted`

`priority/awaiting-more-evidence`: may be useful, but there is not yet enough support.


# Weekly Triage

Weekly triage has three goals:

1. Catching up on unresponded issues
1. Reviewing and closing PR’s
1. Closing stale issues


## Post-Release Triage

Post-release triage occurs after a major release (around every 4-6 weeks).
It focuses on:

1. Closing bugs that have been resolved by the release
1. Reprioritizing bugs that have not been resolved by the release
1. Letting users know if we believe that there is still an issue

This includes reviewing:

1. Every issue that hasn’t been touched in the last 2 days
1. Re-evaluation of long-term issues
1. Re-evaluation of short-term issues


## Responding to Issues

### Needs More Information
A sample response to ask for more info:

> I don’t yet have a clear way to replicate this issue. Do you mind adding some additional details. Here is additional information that would be helpful:
>
> \*  The exact `trivy` command line used
>
> \*  The exact image you want to scan
>
> \*  The full output of the `trivy` command, preferably with `--debug` for extra logging.
>
>
> Thank you for sharing your experience!


Then: Label with `triage/needs-information`.

### Issue might be resolved
If you think a release may have resolved an issue, ask the author to see if their issue has been resolved:

> Could you please check to see if trivy <x> addresses this issue? We've made some changes with how this is handled, and improved the trivy logs output to help us debug tricky cases like this.

Then: Label with `triage/needs-information`.


## Closing with Care

Issues typically need to be closed for the following reasons:

- The issue has been addressed
- The issue is a duplicate of an existing issue
- There has been a lack of information over a long period of time

In any of these situations, we aim to be kind when closing the issue, and offer the author action items should they need to reopen their issue or still require a solution.

Samples responses for these situations include:

### Issue has been addressed

>@author: I believe this issue is now addressed by trivy v1.0.0, as it <reason>. If you still see this issue with trivy v1.0 or higher, please reopen this issue.
>
>Thank you for reporting this issue!

Then: Close the issue

### Duplicate Issue

>This issue appears to be a duplicate of #X, do you mind if we move the conversation there?
>
>This way we can centralize the content relating to the issue. If you feel that this issue is not in fact a duplicate, please re-open it. If you have additional information to share, please add it to the new issue.
>
>Thank you for reporting this!

Then: Label with `triage/duplicate` and close the issue.

### Lack of Information
If an issue hasn't been active for more than four weeks, and the author has been pinged at least once, then the issue can be closed.

>Hey @author -- hopefully it's OK if I close this - there wasn't enough information to make it actionable, and some time has already passed. If you are able to provide additional details, you may reopen it at any point.
> 
>Here is additional information that may be helpful to us:
>
>\* Whether the issue occurs with the latest trivy release
>
>\* The exact `trivy` command line used
>
>\* The exact image you want to scan
>
>\* The full output of the `trivy` command, preferably with `--debug` for extra logging.
>
>
>Thank you for sharing your experience!

Then: Close the issue.

## Help Wanted issues

We use two labels [help wanted](https://github.com/aquasecurity/trivy/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22)
and [good first issue](https://github.com/aquasecurity/trivy/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
to identify issues that have been specially groomed for new contributors.

We have specific [guidelines](/docs/advanced/contribd/contrib/help-wanted.md)
for how to use these labels. If you see an issue that satisfies these
guidelines, you can add the `help wanted` label and the `good first issue` label.
Please note that adding the `good first issue` label must also 
add the `help wanted` label.

If an issue has these labels but does not satisfy the guidelines, please
ask for more details to be added to the issue or remove the labels.
