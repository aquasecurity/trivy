#!/bin/bash
set -e

export GITHUB_TOKEN=""
goreleaser release --snapshot --clean --config=goreleaser.yml
