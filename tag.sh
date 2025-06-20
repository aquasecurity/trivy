#!/bin/bash
set -e

TAG="v0.56.2-maven-patch"

sed -i '' -E "s/(var ver = \")[^\"]+(\")/\1$TAG\2/" pkg/version/app/version.go

if ! git diff --quiet pkg/version/app/version.go; then
  git add pkg/version/app/version.go
  git commit -m "Update tag to $TAG"
  git push
else
  echo "version.go is already up-to-date"
fi

git tag --force $TAG
git push --force --tags