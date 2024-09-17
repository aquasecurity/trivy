#!/bin/bash

set -e

VERSION=$1

# Update version in file
echo "Update Chart.yaml with Trivy $VERSION"
sed -i "s/version: [0-9]\+\.[0-9]\+\.[0-9]\+/version: $VERSION/" ./helm/trivy/Chart.yaml
sed -i "s/appVersion: [0-9]\+\.[0-9]\+\.[0-9]\+/appVersion: $VERSION/" ./helm/trivy/Chart.yaml

echo "Create PR for update Trivy $VERSION in the Helm Chart"

# Create a new branch
NEW_BRANCH="ci/bump-trivy-to-$VERSION"

echo "Creating new branch: $NEW_BRANCH"
git switch -c "$NEW_BRANCH"

# Create the title
TITLE="ci(helm): bump Trivy version to $VERSION"

# commit Helm Values with a new version
git add ./helm/trivy/Chart.yaml
git commit -m "$TITLE"

# Create the pull request description
PR_DESCRIPTION="# Description

This PR bumps Trivy up to the $VERSION version for the Helm chart."

echo "Pushing new branch to origin: $NEW_BRANCH"
git push origin "$NEW_BRANCH"

echo "Pull request title: $TITLE"

echo "Pull request description:"
echo "$PR_DESCRIPTION"

# Create a new pull request
echo "Creating pull request..."
gh pr create --base main --head "$NEW_BRANCH" --title "$TITLE" --body "$PR_DESCRIPTION" --repo "$GITHUB_REPOSITORY" --label "helm-chart"