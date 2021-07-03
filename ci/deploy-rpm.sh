#!/bin/bash

function generate_rpm_macros() {
        echo "%_signature gpg" > ~/.rpmmacros
        echo "%_gpg_path ${HOME}/.gnupg" >> ~/.rpmmacros
        echo "%_gpg_name Amir Jerbi" >> ~/.rpmmacros
        echo "%_gpgbin /usr/bin/gpg" >> ~/.rpmmacros
        echo "%__gpg_sign_cmd %{__gpg} gpg --force-v3-sigs --batch --verbose --no-armor --no-secmem-warning -u \"%{_gpg_name}\" -sbo %{__signature_filename} --digest-algo sha256 %{__plaintext_filename}'" >> ~/.rpmmacros
}

function cache_rpm_gpg_key() {
        echo "allow-preset-passphrase" >> ~/.gnupg/gpg-agent.conf
        gpg-connect-agent reloadagent /bye
        KEY_ID=$(gpg --list-keys | grep -ws aquasec -B 1 | grep -iv uid | sed 's/^ *//;s/ *$//')
        KEYGRIP=$(gpg --with-keygrip -k ${KEY_ID} | grep -ws ${KEY_ID} -A 1 | grep -iv ${KEY_ID} | sed s/"Keygrip = "// | sed 's/^ *//;s/ *$//')         
        /usr/lib/gnupg2/gpg-preset-passphrase --passphrase ${PASSPHRASE} --preset ${KEYGRIP} 
}

function create_rpm_repo () {
        version=$1
        rpm_path=rpm/releases/${version}/x86_64

        RPM_EL=$(find ../dist/ -type f -name "*64bit.rpm" -printf "%f\n" | head -n1 | sed -e "s/_/-/g" -e "s/-Linux/.el$version/" -e "s/-64bit/.x86_64/")
        echo $RPM_EL

        rpm --addsign ../dist/*64bit.rpm

        mkdir -p $rpm_path
        cp ../dist/*64bit.rpm ${rpm_path}/${RPM_EL}

        createrepo --update $rpm_path
}

cd trivy-repo

cache_rpm_gpg_key
generate_rpm_macros

VERSIONS=(5 6 7 8)
for version in ${VERSIONS[@]}; do
        echo "Processing RHEL/CentOS $version..."
        create_rpm_repo $version
done

git add .
git commit -m "Update rpm packages"
git push origin main
