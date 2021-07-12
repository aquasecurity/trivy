# Overview

We use two labels [help wanted](#help-wanted) and [good first
issue](#good-first-issue) to identify issues that have been specially groomed
for new contributors. The `good first issue` label is a subset of `help wanted`
label, indicating that members have committed to providing extra assistance for
new contributors. All `good first issue` items also have the `help wanted`
label.

## Help Wanted

Items marked with the `help wanted` label need to ensure that they are:

- **Low Barrier to Entry**

  It should be tractable for new contributors. Documentation on how that type of
  change should be made should already exist.

- **Clear Task**

  The task is agreed upon and does not require further discussions in the
  community. Call out if that area of code is untested and requires new
  fixtures.

  API / CLI behavior is decided and included in the OP issue, for example: "The
  new command syntax is `trivy --format yaml IMAGE_NAME`"_ with
  expected validations called out.

- **Goldilocks priority**

  Not too high that a core contributor should do it, but not too low that it
  isn't useful enough for a core contributor to spend time to review it, answer
  questions, help get it into a release, etc.

- **Up-To-Date**

  Often these issues become obsolete and have already been done, are no longer
  desired, no longer make sense, have changed priority or difficulty , etc.


## Good First Issue

Items marked with the `good first issue` label are intended for _first-time
contributors_. It indicates that members will keep an eye out for these pull
requests and shepherd it through our processes.

These items need to ensure that they follow the guidelines for `help wanted`
labels (above) in addition to meeting the following criteria:

- **No Barrier to Entry**

  The task is something that a new contributor can tackle without advanced
  setup, or domain knowledge.

- **Solution Explained**

  The recommended solution is clearly described in the issue.

- **Provides Context**

  If background knowledge is required, this should be explicitly mentioned and a
  list of suggested readings included.

- **Gives Examples**

  Link to examples of similar implementations so new contributors have a
  reference guide for their changes.

- **Identifies Relevant Code**

  The relevant code and tests to be changed should be linked in the issue.

- **Ready to Test**

  There should be existing tests that can be modified, or existing test cases
  fit to be copied. If the area of code doesn't have tests, before labeling the
  issue, add a test fixture. This prep often makes a great `help wanted` task!
  
