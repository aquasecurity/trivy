#!/bin/bash

TRIVY_VERSION=$(find ../dist/ -type f -name "*64bit.rpm" -printf "%f\n" | head -n1 | sed -nre 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')

function create_rpm_repo () {
        version=$1
        rpm_path=rpm/releases/${version}/x86_64

        mkdir -p $rpm_path
        cp ../dist/*64bit.rpm ${rpm_path}/

        createrepo_c -u https://github.com/aquasecurity/trivy/releases/download/ --location-prefix="v"$TRIVY_VERSION --update $rpm_path

        rm ${rpm_path}/*64bit.rpm
}

echo "Create RPM releases for Trivy v$TRIVY_VERSION"

cd trivy-repo

VERSIONS=(5 6 7 8 9)
for version in ${VERSIONS[@]}; do
        echo "Processing RHEL/CentOS $version..."
        create_rpm_repo $version
done

git add .
git commit -m "Update rpm packages for Trivy v$TRIVY_VERSION"
git push origin main
