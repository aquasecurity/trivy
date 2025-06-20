#!/bin/bash
set -e

if [ -n "$GITHUB_TOKEN" ]; then
  :
elif [ -f .github-pat ]; then
  export GITHUB_TOKEN=$(<.github-pat)
else
  echo "Error: GITHUB_TOKEN token is missing, please set it via the GITHUB_TOKEN environment variable or the .github-pat file. exit 1"
  exit 1
fi

goreleaser release --clean --config=goreleaser.yml
