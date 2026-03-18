#!/bin/bash

TRIVY_VERSION=$(find dist/ -type f -name "*64bit.rpm" -printf "%f\n" | head -n1 | sed -nre 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')

function create_common_rpm_repo () {
        rpm_path=$1

        ARCHES=("x86_64" "aarch64")
        for arch in ${ARCHES[@]}; do
                prefix=$arch
                if [ "$arch" == "x86_64" ]; then
                        prefix="64bit"
                elif [ "$arch" == "aarch64" ]; then
                        prefix="ARM64"
                fi

                mkdir -p $rpm_path/$arch
                cp ../dist/*${prefix}.rpm ${rpm_path}/$arch/
                createrepo_c -u https://get.trivy.dev/rpm/ --location-prefix="v"$TRIVY_VERSION --update $rpm_path/$arch
                rm ${rpm_path}/$arch/*${prefix}.rpm
        done
}

function create_rpm_repo () {
        version=$1
        rpm_path=rpm/releases/${version}/x86_64

        mkdir -p $rpm_path

        rpm_tmp=rpm/releases/${version}/tmp

        mkdir -p $rpm_tmp
        cp ../dist/*64bit.rpm ${rpm_tmp}/

        rpm_old=rpm/releases/${version}/old
        mkdir -p $rpm_old

        createrepo_c -u https://get.trivy.dev/rpm/ --location-prefix="v"$TRIVY_VERSION --update $rpm_tmp

        if [ -d "$rpm_path/repodata" ]; then
                # Preserve existing metadata by merging with new repo metadata
                cp -r $rpm_path/repodata $rpm_old/
                mergerepo_c -v --all -r $rpm_old -r $rpm_tmp -o $rpm_path
        else
                # No existing repo: initialize from the new metadata
                rm -rf $rpm_path/repodata
                mkdir -p $rpm_path
                cp -r $rpm_tmp/repodata $rpm_path/
        fi

        rm -rf $rpm_tmp
        rm -rf $rpm_old

        rm -f ${rpm_path}/*64bit.rpm
}

echo "Create RPM releases for Trivy v$TRIVY_VERSION"

cd trivy-repo

echo "Processing common repository for RHEL/CentOS..."
create_common_rpm_repo rpm/releases

VERSIONS=(5 6 7 8 9)
for version in ${VERSIONS[@]}; do
        echo "Processing RHEL/CentOS $version..."
        create_rpm_repo $version
done

git add .
git commit -m "Update rpm packages for Trivy v$TRIVY_VERSION"
git push origin main
