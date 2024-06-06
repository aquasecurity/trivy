#!/bin/bash

set -e

BRANCH_NAME=$1
PR_NUMBER=$2

echo "Backporting PR #$PR_NUMBER to branch $BRANCH_NAME"

# Get the merge commit hash of the pull request
echo "Fetching merge commit hash of PR #$PR_NUMBER..."
COMMIT_HASH=$(gh api /repos/"$GITHUB_REPOSITORY"/pulls/"$PR_NUMBER" | jq -r '.merge_commit_sha')
echo "Merge commit hash: $COMMIT_HASH"

# Get the title of the original pull request
echo "Fetching title of PR #$PR_NUMBER..."
ORIGINAL_PR_TITLE=$(gh api /repos/"$GITHUB_REPOSITORY"/pulls/"$PR_NUMBER" | jq -r '.title')
echo "Original PR title: $ORIGINAL_PR_TITLE"

# Checkout the base branch
echo "Checking out base branch: $BRANCH_NAME"
git checkout "$BRANCH_NAME"

# Create a new branch with the PR number and branch name
NEW_BRANCH="backport-pr-$PR_NUMBER-to-$BRANCH_NAME"

echo "Creating new branch: $NEW_BRANCH"
git switch -c "$NEW_BRANCH"

# Create the pull request title
PR_TITLE="$ORIGINAL_PR_TITLE [backport: $BRANCH_NAME]"

# Create the pull request description
PR_DESCRIPTION="# Backport

This will backport the following commits from \`main\` to \`$BRANCH_NAME\`:
 - https://github.com/$GITHUB_REPOSITORY/pull/$PR_NUMBER"

echo "Cherry-picking commit: $COMMIT_HASH"
if git cherry-pick "$COMMIT_HASH"; then
  echo "Cherry-pick successful"
else
  echo "Cherry-pick failed due to conflicts, force-committing changes"

  # Add only conflicted files
  git diff --name-only --diff-filter=U | xargs git add

  # Force-commit the changes with conflicts
  git commit -m "Force-committed changes with conflicts for cherry-pick of $COMMIT_HASH"

  PR_DESCRIPTION="$PR_DESCRIPTION

## ⚠️ Warning
Conflicts occurred during the cherry-pick and were force-committed without proper resolution. Please carefully review the changes, resolve any remaining conflicts, and ensure the code is in a valid state."
fi

echo "Pushing new branch to origin: $NEW_BRANCH"
git push origin "$NEW_BRANCH"

echo "Pull request title: $PR_TITLE"

echo "Pull request description:"
echo "$PR_DESCRIPTION"

# Create a new pull request with the original PR title, backport suffix, and description
echo "Creating pull request..."
gh pr create --base "$BRANCH_NAME" --head "$NEW_BRANCH" --title "$PR_TITLE" --body "$PR_DESCRIPTION" --repo "$GITHUB_REPOSITORY" --label "backport"

# Add a comment to the original PR
echo "Adding comment to the original PR #$PR_NUMBER"
gh pr comment "$PR_NUMBER" --body "Backport PR created: https://github.com/$GITHUB_REPOSITORY/pull/$(gh pr view "$NEW_BRANCH" --json number --jq .number)"