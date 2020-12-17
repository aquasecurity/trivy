#!/bin/bash

DEBIAN_RELEASES=$(debian-distro-info --supported)
UBUNTU_RELEASES=$(ubuntu-distro-info --supported)

cd trivy-repo/deb

for release in ${DEBIAN_RELEASES[@]} ${UBUNTU_RELEASES[@]}; do
  echo "Removing deb package of $release"
  reprepro -A i386 remove $release trivy
  reprepro -A amd64 remove $release trivy
done

for release in ${DEBIAN_RELEASES[@]} ${UBUNTU_RELEASES[@]}; do
  echo "Adding deb package to $release"
  reprepro includedeb $release ../../dist/*Linux-64bit.deb
  reprepro includedeb $release ../../dist/*Linux-32bit.deb
done

git add .
git commit -m "Update deb packages"
git push origin main
