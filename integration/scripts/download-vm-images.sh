#!/bin/bash

TEST_VM=ghcr.io/aquasecurity/trivy-test-vm-images

CRANE_IMG=gcr.io/go-containerregistry/crane:v0.12.1
ORAS_IMG=ghcr.io/oras-project/oras:v0.16.0

CURRENT=$(cd $(dirname $0);pwd)

mkdir -p ${CURRENT}/../testdata/fixtures/vm-images/

# List the tags
TAGS=$(docker run --rm ${CRANE_IMG} ls ${TEST_VM})

# Download missing images
for tag in $TAGS
do
  dir=${CURRENT}/../testdata/fixtures/vm-images/
  if [ ! -e "${dir}/${tag}.img.gz" ] || [ ! -e "${dir}/${tag}.vmdk.gz" ]; then
    echo "Downloading $tag..."
    echo "oras pull ${TEST_VM}:${tag}"
    docker run --rm -v ${dir}:/workspace ${ORAS_IMG} pull "${TEST_VM}:${tag}"
  fi
done