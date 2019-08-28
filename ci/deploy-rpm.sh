#!/bin/bash

function create_rpm_repo () {
        version=$1

        RPM_EL=$(find ../dist/ -type f -name "*64bit.rpm" -printf "%f\n" | head -n1 | sed -e "s/_/-/g" -e "s/-Linux/.el$version/" -e "s/-64bit/.x86_64/")
        echo $RPM_EL

        mkdir -p rpm/releases/${version}/x86_64
        cp ../dist/*64bit.rpm rpm/releases/${version}/x86_64/${RPM_EL}

        createrepo --update rpm/releases/${version}/x86_64/
}

cd trivy-repo

VERSIONS=(5 6 7 8)
for version in ${VERSIONS[@]}; do
        echo "Processing RHEL/CentOS $version..."
        create_rpm_repo $version
done

git add .
git commit -m "Update rpm packages"
git push origin master

