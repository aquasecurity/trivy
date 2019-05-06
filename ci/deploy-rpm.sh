#!/bin/sh

RPM_EL6=$(find dist/ -type f -name "*64bit.rpm" -printf "%f\n" | head -n1 | sed -e 's/_/-/g' -e 's/-Linux/.el6/' -e 's/-64bit/.x86_64/')
RPM_EL7=$(find dist/ -type f -name "*64bit.rpm" -printf "%f\n" | head -n1 | sed -e 's/_/-/g' -e 's/-Linux/.el7/' -e 's/-64bit/.x86_64/')

cd trivy-repo
mkdir -p rpm/releases/6/x86_64
mkdir -p rpm/releases/7/x86_64

cd rpm
cp ../../dist/*64bit.rpm releases/6/x86_64/${RPM_EL6}
cp ../../dist/*64bit.rpm releases/7/x86_64/${RPM_EL7}

createrepo --update releases/6/x86_64/
createrepo --update releases/7/x86_64/

git add .
git commit -m "Update rpm packages"
git push origin master

