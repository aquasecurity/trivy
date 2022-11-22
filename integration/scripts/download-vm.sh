#!/bin/bash

TEST_VM=ghcr.io/masahiro331/test-vm

CURRENT=$(cd $(dirname $0);pwd)

mkdir -p ${CURRENT}/../testdata/fixtures/vm/

# List the tags
TAGS=$(crane ls ${TEST_VM})

# Download missing images
for tag in $TAGS
do
  dir=${CURRENT}/../testdata/fixtures/vm/
  if [ ! -e "${dir}/${tag}.img.gz" ]; then
    echo "Downloading $tag..."
    echo "crane pull ${TEST_VM}:${tag} ${dir}/${tag}"
    crane pull "${TEST_VM}:${tag}" "${dir}/${tag}"
  fi
done