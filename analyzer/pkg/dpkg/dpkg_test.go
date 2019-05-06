package dpkg

import (
	"bufio"
	"os"
	"sort"
	"testing"

	"github.com/d4l3k/messagediff"

	"github.com/knqyf263/fanal/analyzer"
)

func TestParseApkInfo(t *testing.T) {
	var tests = map[string]struct {
		path string
		pkgs []analyzer.Package
	}{
		"Valid": {
			path: "./testdata/dpkg",
			pkgs: []analyzer.Package{
				{Name: "acl", Version: "2.2.52-3build1", Type: "source"},
				{Name: "adduser", Version: "3.116ubuntu1", Type: "binary"},
				{Name: "adduser", Version: "3.116ubuntu1", Type: "source"},
				{Name: "apt", Version: "1.6.3ubuntu0.1", Type: "binary"},
				{Name: "apt", Version: "1.6.3ubuntu0.1", Type: "source"},
				{Name: "attr", Version: "1:2.4.47-2build1", Type: "source"},
				{Name: "audit", Version: "1:2.8.2-1ubuntu1", Type: "source"},
				{Name: "base-files", Version: "10.1ubuntu2.2", Type: "binary"},
				{Name: "base-files", Version: "10.1ubuntu2.2", Type: "source"},
				{Name: "base-passwd", Version: "3.5.44", Type: "binary"},
				{Name: "base-passwd", Version: "3.5.44", Type: "source"},
				{Name: "bash", Version: "4.4.18-2ubuntu1", Type: "binary"},
				{Name: "bash", Version: "4.4.18-2ubuntu1", Type: "source"},
				{Name: "bsdutils", Version: "1:2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "bzip2", Version: "1.0.6-8.1", Type: "binary"},
				{Name: "bzip2", Version: "1.0.6-8.1", Type: "source"},
				{Name: "cdebconf", Version: "0.213ubuntu1", Type: "source"},
				{Name: "coreutils", Version: "8.28-1ubuntu1", Type: "binary"},
				{Name: "coreutils", Version: "8.28-1ubuntu1", Type: "source"},
				{Name: "dash", Version: "0.5.8-2.10", Type: "binary"},
				{Name: "dash", Version: "0.5.8-2.10", Type: "source"},
				{Name: "db5.3", Version: "5.3.28-13.1ubuntu1", Type: "source"},
				{Name: "debconf", Version: "1.5.66", Type: "binary"},
				{Name: "debconf", Version: "1.5.66", Type: "source"},
				{Name: "debianutils", Version: "4.8.4", Type: "binary"},
				{Name: "debianutils", Version: "4.8.4", Type: "source"},
				{Name: "diffutils", Version: "1:3.6-1", Type: "binary"},
				{Name: "diffutils", Version: "1:3.6-1", Type: "source"},
				{Name: "dpkg", Version: "1.19.0.5ubuntu2", Type: "binary"},
				{Name: "dpkg", Version: "1.19.0.5ubuntu2", Type: "source"},
				{Name: "e2fsprogs", Version: "1.44.1-1", Type: "binary"},
				{Name: "e2fsprogs", Version: "1.44.1-1", Type: "source"},
				{Name: "fdisk", Version: "2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "findutils", Version: "4.6.0+git+20170828-2", Type: "binary"},
				{Name: "findutils", Version: "4.6.0+git+20170828-2", Type: "source"},
				{Name: "gcc-8", Version: "8-20180414-1ubuntu2", Type: "source"},
				{Name: "gcc-8-base", Version: "8-20180414-1ubuntu2", Type: "binary"},
				{Name: "glibc", Version: "2.27-3ubuntu1", Type: "source"},
				{Name: "gmp", Version: "2:6.1.2+dfsg-2", Type: "source"},
				{Name: "gnupg2", Version: "2.2.4-1ubuntu1.1", Type: "source"},
				{Name: "gnutls28", Version: "3.5.18-1ubuntu1", Type: "source"},
				{Name: "gpgv", Version: "2.2.4-1ubuntu1.1", Type: "binary"},
				{Name: "grep", Version: "3.1-2", Type: "binary"},
				{Name: "grep", Version: "3.1-2", Type: "source"},
				{Name: "gzip", Version: "1.6-5ubuntu1", Type: "binary"},
				{Name: "gzip", Version: "1.6-5ubuntu1", Type: "source"},
				{Name: "hostname", Version: "3.20", Type: "binary"},
				{Name: "hostname", Version: "3.20", Type: "source"},
				{Name: "init-system-helpers", Version: "1.51", Type: "binary"},
				{Name: "init-system-helpers", Version: "1.51", Type: "source"},
				{Name: "libacl1", Version: "2.2.52-3build1", Type: "binary"},
				{Name: "libapt-pkg5.0", Version: "1.6.3ubuntu0.1", Type: "binary"},
				{Name: "libattr1", Version: "1:2.4.47-2build1", Type: "binary"},
				{Name: "libaudit-common", Version: "1:2.8.2-1ubuntu1", Type: "binary"},
				{Name: "libaudit1", Version: "1:2.8.2-1ubuntu1", Type: "binary"},
				{Name: "libblkid1", Version: "2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "libbz2-1.0", Version: "1.0.6-8.1", Type: "binary"},
				{Name: "libc-bin", Version: "2.27-3ubuntu1", Type: "binary"},
				{Name: "libc6", Version: "2.27-3ubuntu1", Type: "binary"},
				{Name: "libcap-ng", Version: "0.7.7-3.1", Type: "source"},
				{Name: "libcap-ng0", Version: "0.7.7-3.1", Type: "binary"},
				{Name: "libcom-err2", Version: "1.44.1-1", Type: "binary"},
				{Name: "libdb5.3", Version: "5.3.28-13.1ubuntu1", Type: "binary"},
				{Name: "libdebconfclient0", Version: "0.213ubuntu1", Type: "binary"},
				{Name: "libext2fs2", Version: "1.44.1-1", Type: "binary"},
				{Name: "libfdisk1", Version: "2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "libffi", Version: "3.2.1-8", Type: "source"},
				{Name: "libffi6", Version: "3.2.1-8", Type: "binary"},
				{Name: "libgcc1", Version: "1:8-20180414-1ubuntu2", Type: "binary"},
				{Name: "libgcrypt20", Version: "1.8.1-4ubuntu1.1", Type: "binary"},
				{Name: "libgcrypt20", Version: "1.8.1-4ubuntu1.1", Type: "source"},
				{Name: "libgmp10", Version: "2:6.1.2+dfsg-2", Type: "binary"},
				{Name: "libgnutls30", Version: "3.5.18-1ubuntu1", Type: "binary"},
				{Name: "libgpg-error", Version: "1.27-6", Type: "source"},
				{Name: "libgpg-error0", Version: "1.27-6", Type: "binary"},
				{Name: "libhogweed4", Version: "3.4-1", Type: "binary"},
				{Name: "libidn2", Version: "2.0.4-1.1build2", Type: "source"},
				{Name: "libidn2-0", Version: "2.0.4-1.1build2", Type: "binary"},
				{Name: "liblz4-1", Version: "0.0~r131-2ubuntu3", Type: "binary"},
				{Name: "liblzma5", Version: "5.2.2-1.3", Type: "binary"},
				{Name: "libmount1", Version: "2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "libncurses5", Version: "6.1-1ubuntu1.18.04", Type: "binary"},
				{Name: "libncursesw5", Version: "6.1-1ubuntu1.18.04", Type: "binary"},
				{Name: "libnettle6", Version: "3.4-1", Type: "binary"},
				{Name: "libp11-kit0", Version: "0.23.9-2", Type: "binary"},
				{Name: "libpam-modules", Version: "1.1.8-3.6ubuntu2", Type: "binary"},
				{Name: "libpam-modules-bin", Version: "1.1.8-3.6ubuntu2", Type: "binary"},
				{Name: "libpam-runtime", Version: "1.1.8-3.6ubuntu2", Type: "binary"},
				{Name: "libpam0g", Version: "1.1.8-3.6ubuntu2", Type: "binary"},
				{Name: "libpcre3", Version: "2:8.39-9", Type: "binary"},
				{Name: "libprocps6", Version: "2:3.3.12-3ubuntu1.1", Type: "binary"},
				{Name: "libseccomp", Version: "2.3.1-2.1ubuntu4", Type: "source"},
				{Name: "libseccomp2", Version: "2.3.1-2.1ubuntu4", Type: "binary"},
				{Name: "libselinux", Version: "2.7-2build2", Type: "source"},
				{Name: "libselinux1", Version: "2.7-2build2", Type: "binary"},
				{Name: "libsemanage", Version: "2.7-2build2", Type: "source"},
				{Name: "libsemanage-common", Version: "2.7-2build2", Type: "binary"},
				{Name: "libsemanage1", Version: "2.7-2build2", Type: "binary"},
				{Name: "libsepol", Version: "2.7-1", Type: "source"},
				{Name: "libsepol1", Version: "2.7-1", Type: "binary"},
				{Name: "libsmartcols1", Version: "2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "libss2", Version: "1.44.1-1", Type: "binary"},
				{Name: "libstdc++6", Version: "8-20180414-1ubuntu2", Type: "binary"},
				{Name: "libsystemd0", Version: "237-3ubuntu10.3", Type: "binary"},
				{Name: "libtasn1-6", Version: "4.13-2", Type: "binary"},
				{Name: "libtasn1-6", Version: "4.13-2", Type: "source"},
				{Name: "libtinfo5", Version: "6.1-1ubuntu1.18.04", Type: "binary"},
				{Name: "libudev1", Version: "237-3ubuntu10.3", Type: "binary"},
				{Name: "libunistring", Version: "0.9.9-0ubuntu1", Type: "source"},
				{Name: "libunistring2", Version: "0.9.9-0ubuntu1", Type: "binary"},
				{Name: "libuuid1", Version: "2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "libzstd", Version: "1.3.3+dfsg-2ubuntu1", Type: "source"},
				{Name: "libzstd1", Version: "1.3.3+dfsg-2ubuntu1", Type: "binary"},
				{Name: "login", Version: "1:4.5-1ubuntu1", Type: "binary"},
				{Name: "lsb", Version: "9.20170808ubuntu1", Type: "source"},
				{Name: "lsb-base", Version: "9.20170808ubuntu1", Type: "binary"},
				{Name: "lz4", Version: "0.0~r131-2ubuntu3", Type: "source"},
				{Name: "mawk", Version: "1.3.3-17ubuntu3", Type: "binary"},
				{Name: "mawk", Version: "1.3.3-17ubuntu3", Type: "source"},
				{Name: "mount", Version: "2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "ncurses", Version: "6.1-1ubuntu1.18.04", Type: "source"},
				{Name: "ncurses-base", Version: "6.1-1ubuntu1.18.04", Type: "binary"},
				{Name: "ncurses-bin", Version: "6.1-1ubuntu1.18.04", Type: "binary"},
				{Name: "nettle", Version: "3.4-1", Type: "source"},
				{Name: "p11-kit", Version: "0.23.9-2", Type: "source"},
				{Name: "pam", Version: "1.1.8-3.6ubuntu2", Type: "source"},
				{Name: "passwd", Version: "1:4.5-1ubuntu1", Type: "binary"},
				{Name: "pcre3", Version: "2:8.39-9", Type: "source"},
				{Name: "perl", Version: "5.26.1-6ubuntu0.2", Type: "source"},
				{Name: "perl-base", Version: "5.26.1-6ubuntu0.2", Type: "binary"},
				{Name: "procps", Version: "2:3.3.12-3ubuntu1.1", Type: "binary"},
				{Name: "procps", Version: "2:3.3.12-3ubuntu1.1", Type: "source"},
				{Name: "sed", Version: "4.4-2", Type: "binary"},
				{Name: "sed", Version: "4.4-2", Type: "source"},
				{Name: "sensible-utils", Version: "0.0.12", Type: "binary"},
				{Name: "sensible-utils", Version: "0.0.12", Type: "source"},
				{Name: "shadow", Version: "1:4.5-1ubuntu1", Type: "source"},
				{Name: "systemd", Version: "237-3ubuntu10.3", Type: "source"},
				{Name: "sysvinit", Version: "2.88dsf-59.10ubuntu1", Type: "source"},
				{Name: "sysvinit-utils", Version: "2.88dsf-59.10ubuntu1", Type: "binary"},
				{Name: "tar", Version: "1.29b-2", Type: "binary"},
				{Name: "tar", Version: "1.29b-2", Type: "source"},
				{Name: "ubuntu-keyring", Version: "2018.02.28", Type: "binary"},
				{Name: "ubuntu-keyring", Version: "2018.02.28", Type: "source"},
				{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.1", Type: "binary"},
				{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.1", Type: "source"},
				{Name: "xz-utils", Version: "5.2.2-1.3", Type: "source"},
				{Name: "zlib", Version: "1:1.2.11.dfsg-0ubuntu2", Type: "source"},
				{Name: "zlib1g", Version: "1:1.2.11.dfsg-0ubuntu2", Type: "binary"},
			},
		},
		"Corrupsed": {
			path: "./testdata/corrupsed",
			pkgs: []analyzer.Package{
				{Name: "gcc-5", Version: "5.1.1-12ubuntu1", Type: "source"},
				{Name: "libgcc1", Version: "1:5.1.1-12ubuntu1", Type: "binary"},
				{Name: "libpam-modules-bin", Version: "1.1.8-3.1ubuntu3", Type: "binary"},
				{Name: "libpam-runtime", Version: "1.1.8-3.1ubuntu3", Type: "binary"},
				{Name: "makedev", Version: "2.3.1-93ubuntu1", Type: "binary"},
				{Name: "makedev", Version: "2.3.1-93ubuntu1", Type: "source"},
				{Name: "pam", Version: "1.1.8-3.1ubuntu3", Type: "source"},
			},
		},
		"OnlyApt": {
			path: "./testdata/dpkg_apt",
			pkgs: []analyzer.Package{
				{Name: "apt", Version: "1.6.3ubuntu0.1", Type: "binary"},
				{Name: "apt", Version: "1.6.3ubuntu0.1", Type: "source"},
			},
		},
	}
	a := debianPkgAnalyzer{}
	for testname, v := range tests {
		read, err := os.Open(v.path)
		if err != nil {
			t.Errorf("%s : can't open file %s", testname, v.path)
		}
		scanner := bufio.NewScanner(read)
		pkgs := a.parseDpkginfo(scanner)
		if err != nil {
			t.Errorf("%s : catch the error : %v", testname, err)
		}
		diff, equal := messagediff.PrettyDiff(v.pkgs, sortPkgByName(pkgs))
		if !equal {
			t.Errorf("[%s]\n diff: %v", testname, diff)
		}
	}
}

func sortPkgByName(pkgs []analyzer.Package) []analyzer.Package {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Type < pkgs[j].Type
	})
	return pkgs
}
