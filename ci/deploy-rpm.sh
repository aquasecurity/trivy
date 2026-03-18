#!/bin/bash

TRIVY_VERSION=$(find dist/ -type f -name "*64bit.rpm" -printf "%f\n" | head -n1 | sed -nre 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')

# Merge freshly generated repo metadata for new RPMs with existing repo metadata
# Arguments:
#   $1 - glob for RPMs to include from ../dist (e.g., "*64bit.rpm")
#   $2 - target repo path where repodata is maintained (e.g., rpm/releases/7/x86_64)
function merge_repo_with_new_packages () {
        rpm_glob=$1
        rpm_path=$2

        mkdir -p "$rpm_path"

        base_dir=$(dirname "$rpm_path")
        rpm_tmp="$base_dir/tmp"
        rpm_old="$base_dir/old"

        mkdir -p "$rpm_tmp"
        mkdir -p "$rpm_old"

        # stage new packages in a temp directory
        cp ../dist/${rpm_glob} "$rpm_tmp"/

        # generate metadata for the staged packages only
        createrepo_c -u https://get.trivy.dev/rpm/ --location-prefix="v"$TRIVY_VERSION --update "$rpm_tmp"

        if [ -d "$rpm_path/repodata" ]; then
                # Preserve existing metadata by merging with new repo metadata
                cp -r "$rpm_path/repodata" "$rpm_old"/
                mergerepo_c -v --all -r "$rpm_old" -r "$rpm_tmp" -o "$rpm_path"
        else
                # No existing repo: initialize from the new metadata
                cp -r "$rpm_tmp/repodata" "$rpm_path"/
        fi

        rm -rf "$rpm_tmp"
        rm -rf "$rpm_old"

        # ensure no RPM files remain in the target repo path
        rm -f "$rpm_path"/*.rpm || true
}

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

                merge_repo_with_new_packages "*${prefix}.rpm" "$rpm_path/$arch"
        done
}

function create_rpm_repo () {
        version=$1
        rpm_path=rpm/releases/${version}/x86_64

        merge_repo_with_new_packages "*64bit.rpm" "$rpm_path"
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
