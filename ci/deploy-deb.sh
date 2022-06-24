#!/bin/bash

DEBIAN_RELEASES=$(debian-distro-info --supported)
UBUNTU_RELEASES=$(sort -u <(ubuntu-distro-info --supported-esm) <(ubuntu-distro-info --supported))

cd trivy-repo/deb

for release in ${DEBIAN_RELEASES[@]} ${UBUNTU_RELEASES[@]}; do
  echo "Removing deb package of $release"
  reprepro -A i386 remove $release trivy
  reprepro -A amd64 remove $release trivy
  reprepro -A arm64 remove $release trivy
done

rm -r conf
mkdir conf

DEBIAN_ALL_RELEASES=$(debian-distro-info --all)
UBUNTU_ALL_RELEASES=$(ubuntu-distro-info --all)

for release in ${DEBIAN_ALL_RELEASES[@]} ${UBUNTU_ALL_RELEASES[@]}; do
  echo "Origin: aquasecurity.github.io/trivy-repo/deb
Label: github.io/aquasecurity
Codename: $release
Architectures: i386 amd64 arm64
Components: main
Description: Trivy repository
SignWith: 2E2D3567461632C84BB6CD6FE9D0A3616276FA6C
" >> conf/distributions
done

for release in ${DEBIAN_RELEASES[@]} ${UBUNTU_RELEASES[@]}; do
  echo "Adding deb package to $release"
  reprepro includedeb $release ../../dist/*Linux-64bit.deb
  reprepro includedeb $release ../../dist/*Linux-32bit.deb
  reprepro includedeb $release ../../dist/*Linux-ARM64.deb
done

git add .
git commit -m "Update deb packages"
git push origin main
