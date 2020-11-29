package rpm

import (
	"io/ioutil"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
)

func TestParseRpmInfo(t *testing.T) {
	var tests = map[string]struct {
		path string
		pkgs []types.Package
	}{
		"Valid": {
			path: "./testdata/valid",
			// cp ./testdata/valid /path/to/testdir/Packages
			// rpm --dbpath /path/to/testdir -qa --qf "{Name: \"%{NAME}\", Epoch: %{EPOCHNUM}, Version: \"%{VERSION}\", Release: \"%{RELEASE}\", Arch: \"%{ARCH}\"\},\n"
			pkgs: []types.Package{
				{Name: "centos-release", Epoch: 0, Version: "7", Release: "1.1503.el7.centos.2.8", Arch: "x86_64", SrcName: "centos-release", SrcEpoch: 0, SrcVersion: "7", SrcRelease: "1.1503.el7.centos.2.8"},
				{Name: "filesystem", Epoch: 0, Version: "3.2", Release: "18.el7", Arch: "x86_64", SrcName: "filesystem", SrcEpoch: 0, SrcVersion: "3.2", SrcRelease: "18.el7"},
			},
		},
		"ValidBig": {
			path: "./testdata/valid_big",
			// $ cat rpmqa.py
			// import rpm
			// from rpmUtils.miscutils import splitFilename
			//
			//
			// rpm.addMacro('_dbpath', '/tmp/')
			// ts = rpm.TransactionSet()
			// mi = ts.dbMatch()
			// for h in mi:
			//     sname = sversion = srelease = ""
			//     if h[rpm.RPMTAG_SOURCERPM] != "(none)":
			//         sname, sversion, srelease, _, _ = splitFilename(h[rpm.RPMTAG_SOURCERPM])
			//     print "{Name: \"%s\", Epoch: %d, Version: \"%s\", Release: \"%s\", Arch: \"%s\", SrcName: \"%s\", SrcEpoch: %d, SrcVersion: \"%s\", SrcRelease: \"%s\"}," % (
			//         h[rpm.RPMTAG_NAME], h[rpm.RPMTAG_EPOCHNUM], h[rpm.RPMTAG_VERSION], h[rpm.RPMTAG_RELEASE], h[rpm.RPMTAG_ARCH],
			//         sname, h[rpm.RPMTAG_EPOCHNUM], sversion, srelease)
			pkgs: []types.Package{
				{Name: "publicsuffix-list-dafsa", Epoch: 0, Version: "20180514", Release: "1.fc28", Arch: "noarch", SrcName: "publicsuffix-list", SrcEpoch: 0, SrcVersion: "20180514", SrcRelease: "1.fc28"},
				{Name: "libreport-filesystem", Epoch: 0, Version: "2.9.5", Release: "1.fc28", Arch: "x86_64", SrcName: "libreport", SrcEpoch: 0, SrcVersion: "2.9.5", SrcRelease: "1.fc28"},
				{Name: "fedora-gpg-keys", Epoch: 0, Version: "28", Release: "5", Arch: "noarch", SrcName: "fedora-repos", SrcEpoch: 0, SrcVersion: "28", SrcRelease: "5"},
				{Name: "fedora-release", Epoch: 0, Version: "28", Release: "2", Arch: "noarch", SrcName: "fedora-release", SrcEpoch: 0, SrcVersion: "28", SrcRelease: "2"},
				{Name: "filesystem", Epoch: 0, Version: "3.8", Release: "2.fc28", Arch: "x86_64", SrcName: "filesystem", SrcEpoch: 0, SrcVersion: "3.8", SrcRelease: "2.fc28"},
				{Name: "tzdata", Epoch: 0, Version: "2018e", Release: "1.fc28", Arch: "noarch", SrcName: "tzdata", SrcEpoch: 0, SrcVersion: "2018e", SrcRelease: "1.fc28"},
				{Name: "pcre2", Epoch: 0, Version: "10.31", Release: "10.fc28", Arch: "x86_64", SrcName: "pcre2", SrcEpoch: 0, SrcVersion: "10.31", SrcRelease: "10.fc28"},
				{Name: "glibc-minimal-langpack", Epoch: 0, Version: "2.27", Release: "32.fc28", Arch: "x86_64", SrcName: "glibc", SrcEpoch: 0, SrcVersion: "2.27", SrcRelease: "32.fc28"},
				{Name: "glibc-common", Epoch: 0, Version: "2.27", Release: "32.fc28", Arch: "x86_64", SrcName: "glibc", SrcEpoch: 0, SrcVersion: "2.27", SrcRelease: "32.fc28"},
				{Name: "bash", Epoch: 0, Version: "4.4.23", Release: "1.fc28", Arch: "x86_64", SrcName: "bash", SrcEpoch: 0, SrcVersion: "4.4.23", SrcRelease: "1.fc28"},
				{Name: "zlib", Epoch: 0, Version: "1.2.11", Release: "8.fc28", Arch: "x86_64", SrcName: "zlib", SrcEpoch: 0, SrcVersion: "1.2.11", SrcRelease: "8.fc28"},
				{Name: "bzip2-libs", Epoch: 0, Version: "1.0.6", Release: "26.fc28", Arch: "x86_64", SrcName: "bzip2", SrcEpoch: 0, SrcVersion: "1.0.6", SrcRelease: "26.fc28"},
				{Name: "libcap", Epoch: 0, Version: "2.25", Release: "9.fc28", Arch: "x86_64", SrcName: "libcap", SrcEpoch: 0, SrcVersion: "2.25", SrcRelease: "9.fc28"},
				{Name: "libgpg-error", Epoch: 0, Version: "1.31", Release: "1.fc28", Arch: "x86_64", SrcName: "libgpg-error", SrcEpoch: 0, SrcVersion: "1.31", SrcRelease: "1.fc28"},
				{Name: "libzstd", Epoch: 0, Version: "1.3.5", Release: "1.fc28", Arch: "x86_64", SrcName: "zstd", SrcEpoch: 0, SrcVersion: "1.3.5", SrcRelease: "1.fc28"},
				{Name: "expat", Epoch: 0, Version: "2.2.5", Release: "3.fc28", Arch: "x86_64", SrcName: "expat", SrcEpoch: 0, SrcVersion: "2.2.5", SrcRelease: "3.fc28"},
				{Name: "nss-util", Epoch: 0, Version: "3.38.0", Release: "1.0.fc28", Arch: "x86_64", SrcName: "nss-util", SrcEpoch: 0, SrcVersion: "3.38.0", SrcRelease: "1.0.fc28"},
				{Name: "libcom_err", Epoch: 0, Version: "1.44.2", Release: "0.fc28", Arch: "x86_64", SrcName: "e2fsprogs", SrcEpoch: 0, SrcVersion: "1.44.2", SrcRelease: "0.fc28"},
				{Name: "libffi", Epoch: 0, Version: "3.1", Release: "16.fc28", Arch: "x86_64", SrcName: "libffi", SrcEpoch: 0, SrcVersion: "3.1", SrcRelease: "16.fc28"},
				{Name: "libgcrypt", Epoch: 0, Version: "1.8.3", Release: "1.fc28", Arch: "x86_64", SrcName: "libgcrypt", SrcEpoch: 0, SrcVersion: "1.8.3", SrcRelease: "1.fc28"},
				{Name: "libxml2", Epoch: 0, Version: "2.9.8", Release: "4.fc28", Arch: "x86_64", SrcName: "libxml2", SrcEpoch: 0, SrcVersion: "2.9.8", SrcRelease: "4.fc28"},
				{Name: "libacl", Epoch: 0, Version: "2.2.53", Release: "1.fc28", Arch: "x86_64", SrcName: "acl", SrcEpoch: 0, SrcVersion: "2.2.53", SrcRelease: "1.fc28"},
				{Name: "sed", Epoch: 0, Version: "4.5", Release: "1.fc28", Arch: "x86_64", SrcName: "sed", SrcEpoch: 0, SrcVersion: "4.5", SrcRelease: "1.fc28"},
				{Name: "libmount", Epoch: 0, Version: "2.32.1", Release: "1.fc28", Arch: "x86_64", SrcName: "util-linux", SrcEpoch: 0, SrcVersion: "2.32.1", SrcRelease: "1.fc28"},
				{Name: "p11-kit", Epoch: 0, Version: "0.23.12", Release: "1.fc28", Arch: "x86_64", SrcName: "p11-kit", SrcEpoch: 0, SrcVersion: "0.23.12", SrcRelease: "1.fc28"},
				{Name: "libidn2", Epoch: 0, Version: "2.0.5", Release: "1.fc28", Arch: "x86_64", SrcName: "libidn2", SrcEpoch: 0, SrcVersion: "2.0.5", SrcRelease: "1.fc28"},
				{Name: "libcap-ng", Epoch: 0, Version: "0.7.9", Release: "4.fc28", Arch: "x86_64", SrcName: "libcap-ng", SrcEpoch: 0, SrcVersion: "0.7.9", SrcRelease: "4.fc28"},
				{Name: "lz4-libs", Epoch: 0, Version: "1.8.1.2", Release: "4.fc28", Arch: "x86_64", SrcName: "lz4", SrcEpoch: 0, SrcVersion: "1.8.1.2", SrcRelease: "4.fc28"},
				{Name: "libassuan", Epoch: 0, Version: "2.5.1", Release: "3.fc28", Arch: "x86_64", SrcName: "libassuan", SrcEpoch: 0, SrcVersion: "2.5.1", SrcRelease: "3.fc28"},
				{Name: "keyutils-libs", Epoch: 0, Version: "1.5.10", Release: "6.fc28", Arch: "x86_64", SrcName: "keyutils", SrcEpoch: 0, SrcVersion: "1.5.10", SrcRelease: "6.fc28"},
				{Name: "glib2", Epoch: 0, Version: "2.56.1", Release: "4.fc28", Arch: "x86_64", SrcName: "glib2", SrcEpoch: 0, SrcVersion: "2.56.1", SrcRelease: "4.fc28"},
				{Name: "systemd-libs", Epoch: 0, Version: "238", Release: "9.git0e0aa59.fc28", Arch: "x86_64", SrcName: "systemd", SrcEpoch: 0, SrcVersion: "238", SrcRelease: "9.git0e0aa59.fc28"},
				{Name: "dbus-libs", Epoch: 1, Version: "1.12.10", Release: "1.fc28", Arch: "x86_64", SrcName: "dbus", SrcEpoch: 1, SrcVersion: "1.12.10", SrcRelease: "1.fc28"},
				{Name: "libtasn1", Epoch: 0, Version: "4.13", Release: "2.fc28", Arch: "x86_64", SrcName: "libtasn1", SrcEpoch: 0, SrcVersion: "4.13", SrcRelease: "2.fc28"},
				{Name: "ca-certificates", Epoch: 0, Version: "2018.2.24", Release: "1.0.fc28", Arch: "noarch", SrcName: "ca-certificates", SrcEpoch: 0, SrcVersion: "2018.2.24", SrcRelease: "1.0.fc28"},
				{Name: "libarchive", Epoch: 0, Version: "3.3.1", Release: "4.fc28", Arch: "x86_64", SrcName: "libarchive", SrcEpoch: 0, SrcVersion: "3.3.1", SrcRelease: "4.fc28"},
				{Name: "openssl", Epoch: 1, Version: "1.1.0h", Release: "3.fc28", Arch: "x86_64", SrcName: "openssl", SrcEpoch: 1, SrcVersion: "1.1.0h", SrcRelease: "3.fc28"},
				{Name: "libusbx", Epoch: 0, Version: "1.0.22", Release: "1.fc28", Arch: "x86_64", SrcName: "libusbx", SrcEpoch: 0, SrcVersion: "1.0.22", SrcRelease: "1.fc28"},
				{Name: "libsemanage", Epoch: 0, Version: "2.8", Release: "2.fc28", Arch: "x86_64", SrcName: "libsemanage", SrcEpoch: 0, SrcVersion: "2.8", SrcRelease: "2.fc28"},
				{Name: "libutempter", Epoch: 0, Version: "1.1.6", Release: "14.fc28", Arch: "x86_64", SrcName: "libutempter", SrcEpoch: 0, SrcVersion: "1.1.6", SrcRelease: "14.fc28"},
				{Name: "mpfr", Epoch: 0, Version: "3.1.6", Release: "1.fc28", Arch: "x86_64", SrcName: "mpfr", SrcEpoch: 0, SrcVersion: "3.1.6", SrcRelease: "1.fc28"},
				{Name: "gnutls", Epoch: 0, Version: "3.6.3", Release: "4.fc28", Arch: "x86_64", SrcName: "gnutls", SrcEpoch: 0, SrcVersion: "3.6.3", SrcRelease: "4.fc28"},
				{Name: "gzip", Epoch: 0, Version: "1.9", Release: "3.fc28", Arch: "x86_64", SrcName: "gzip", SrcEpoch: 0, SrcVersion: "1.9", SrcRelease: "3.fc28"},
				{Name: "acl", Epoch: 0, Version: "2.2.53", Release: "1.fc28", Arch: "x86_64", SrcName: "acl", SrcEpoch: 0, SrcVersion: "2.2.53", SrcRelease: "1.fc28"},
				{Name: "nss-softokn-freebl", Epoch: 0, Version: "3.38.0", Release: "1.0.fc28", Arch: "x86_64", SrcName: "nss-softokn", SrcEpoch: 0, SrcVersion: "3.38.0", SrcRelease: "1.0.fc28"},
				{Name: "nss", Epoch: 0, Version: "3.38.0", Release: "1.0.fc28", Arch: "x86_64", SrcName: "nss", SrcEpoch: 0, SrcVersion: "3.38.0", SrcRelease: "1.0.fc28"},
				{Name: "libmetalink", Epoch: 0, Version: "0.1.3", Release: "6.fc28", Arch: "x86_64", SrcName: "libmetalink", SrcEpoch: 0, SrcVersion: "0.1.3", SrcRelease: "6.fc28"},
				{Name: "libdb-utils", Epoch: 0, Version: "5.3.28", Release: "30.fc28", Arch: "x86_64", SrcName: "libdb", SrcEpoch: 0, SrcVersion: "5.3.28", SrcRelease: "30.fc28"},
				{Name: "file-libs", Epoch: 0, Version: "5.33", Release: "7.fc28", Arch: "x86_64", SrcName: "file", SrcEpoch: 0, SrcVersion: "5.33", SrcRelease: "7.fc28"},
				{Name: "libsss_idmap", Epoch: 0, Version: "1.16.3", Release: "2.fc28", Arch: "x86_64", SrcName: "sssd", SrcEpoch: 0, SrcVersion: "1.16.3", SrcRelease: "2.fc28"},
				{Name: "libsigsegv", Epoch: 0, Version: "2.11", Release: "5.fc28", Arch: "x86_64", SrcName: "libsigsegv", SrcEpoch: 0, SrcVersion: "2.11", SrcRelease: "5.fc28"},
				{Name: "krb5-libs", Epoch: 0, Version: "1.16.1", Release: "13.fc28", Arch: "x86_64", SrcName: "krb5", SrcEpoch: 0, SrcVersion: "1.16.1", SrcRelease: "13.fc28"},
				{Name: "libnsl2", Epoch: 0, Version: "1.2.0", Release: "2.20180605git4a062cf.fc28", Arch: "x86_64", SrcName: "libnsl2", SrcEpoch: 0, SrcVersion: "1.2.0", SrcRelease: "2.20180605git4a062cf.fc28"},
				{Name: "python3-pip", Epoch: 0, Version: "9.0.3", Release: "2.fc28", Arch: "noarch", SrcName: "python-pip", SrcEpoch: 0, SrcVersion: "9.0.3", SrcRelease: "2.fc28"},
				{Name: "python3", Epoch: 0, Version: "3.6.6", Release: "1.fc28", Arch: "x86_64", SrcName: "python3", SrcEpoch: 0, SrcVersion: "3.6.6", SrcRelease: "1.fc28"},
				{Name: "pam", Epoch: 0, Version: "1.3.1", Release: "1.fc28", Arch: "x86_64", SrcName: "pam", SrcEpoch: 0, SrcVersion: "1.3.1", SrcRelease: "1.fc28"},
				{Name: "python3-gobject-base", Epoch: 0, Version: "3.28.3", Release: "1.fc28", Arch: "x86_64", SrcName: "pygobject3", SrcEpoch: 0, SrcVersion: "3.28.3", SrcRelease: "1.fc28"},
				{Name: "python3-smartcols", Epoch: 0, Version: "0.3.0", Release: "2.fc28", Arch: "x86_64", SrcName: "python-smartcols", SrcEpoch: 0, SrcVersion: "0.3.0", SrcRelease: "2.fc28"},
				{Name: "python3-iniparse", Epoch: 0, Version: "0.4", Release: "30.fc28", Arch: "noarch", SrcName: "python-iniparse", SrcEpoch: 0, SrcVersion: "0.4", SrcRelease: "30.fc28"},
				{Name: "openldap", Epoch: 0, Version: "2.4.46", Release: "3.fc28", Arch: "x86_64", SrcName: "openldap", SrcEpoch: 0, SrcVersion: "2.4.46", SrcRelease: "3.fc28"},
				{Name: "libseccomp", Epoch: 0, Version: "2.3.3", Release: "2.fc28", Arch: "x86_64", SrcName: "libseccomp", SrcEpoch: 0, SrcVersion: "2.3.3", SrcRelease: "2.fc28"},
				{Name: "npth", Epoch: 0, Version: "1.5", Release: "4.fc28", Arch: "x86_64", SrcName: "npth", SrcEpoch: 0, SrcVersion: "1.5", SrcRelease: "4.fc28"},
				{Name: "gpgme", Epoch: 0, Version: "1.10.0", Release: "4.fc28", Arch: "x86_64", SrcName: "gpgme", SrcEpoch: 0, SrcVersion: "1.10.0", SrcRelease: "4.fc28"},
				{Name: "json-c", Epoch: 0, Version: "0.13.1", Release: "2.fc28", Arch: "x86_64", SrcName: "json-c", SrcEpoch: 0, SrcVersion: "0.13.1", SrcRelease: "2.fc28"},
				{Name: "libyaml", Epoch: 0, Version: "0.1.7", Release: "5.fc28", Arch: "x86_64", SrcName: "libyaml", SrcEpoch: 0, SrcVersion: "0.1.7", SrcRelease: "5.fc28"},
				{Name: "libpkgconf", Epoch: 0, Version: "1.4.2", Release: "1.fc28", Arch: "x86_64", SrcName: "pkgconf", SrcEpoch: 0, SrcVersion: "1.4.2", SrcRelease: "1.fc28"},
				{Name: "pkgconf-pkg-config", Epoch: 0, Version: "1.4.2", Release: "1.fc28", Arch: "x86_64", SrcName: "pkgconf", SrcEpoch: 0, SrcVersion: "1.4.2", SrcRelease: "1.fc28"},
				{Name: "iptables-libs", Epoch: 0, Version: "1.6.2", Release: "3.fc28", Arch: "x86_64", SrcName: "iptables", SrcEpoch: 0, SrcVersion: "1.6.2", SrcRelease: "3.fc28"},
				{Name: "device-mapper-libs", Epoch: 0, Version: "1.02.146", Release: "5.fc28", Arch: "x86_64", SrcName: "lvm2", SrcEpoch: 0, SrcVersion: "2.02.177", SrcRelease: "5.fc28"},
				{Name: "systemd-pam", Epoch: 0, Version: "238", Release: "9.git0e0aa59.fc28", Arch: "x86_64", SrcName: "systemd", SrcEpoch: 0, SrcVersion: "238", SrcRelease: "9.git0e0aa59.fc28"},
				{Name: "systemd", Epoch: 0, Version: "238", Release: "9.git0e0aa59.fc28", Arch: "x86_64", SrcName: "systemd", SrcEpoch: 0, SrcVersion: "238", SrcRelease: "9.git0e0aa59.fc28"},
				{Name: "elfutils-default-yama-scope", Epoch: 0, Version: "0.173", Release: "1.fc28", Arch: "noarch", SrcName: "elfutils", SrcEpoch: 0, SrcVersion: "0.173", SrcRelease: "1.fc28"},
				{Name: "libcurl", Epoch: 0, Version: "7.59.0", Release: "6.fc28", Arch: "x86_64", SrcName: "curl", SrcEpoch: 0, SrcVersion: "7.59.0", SrcRelease: "6.fc28"},
				{Name: "python3-librepo", Epoch: 0, Version: "1.8.1", Release: "7.fc28", Arch: "x86_64", SrcName: "librepo", SrcEpoch: 0, SrcVersion: "1.8.1", SrcRelease: "7.fc28"},
				{Name: "rpm-plugin-selinux", Epoch: 0, Version: "4.14.1", Release: "9.fc28", Arch: "x86_64", SrcName: "rpm", SrcEpoch: 0, SrcVersion: "4.14.1", SrcRelease: "9.fc28"},
				{Name: "rpm", Epoch: 0, Version: "4.14.1", Release: "9.fc28", Arch: "x86_64", SrcName: "rpm", SrcEpoch: 0, SrcVersion: "4.14.1", SrcRelease: "9.fc28"},
				{Name: "libdnf", Epoch: 0, Version: "0.11.1", Release: "3.fc28", Arch: "x86_64", SrcName: "libdnf", SrcEpoch: 0, SrcVersion: "0.11.1", SrcRelease: "3.fc28"},
				{Name: "rpm-build-libs", Epoch: 0, Version: "4.14.1", Release: "9.fc28", Arch: "x86_64", SrcName: "rpm", SrcEpoch: 0, SrcVersion: "4.14.1", SrcRelease: "9.fc28"},
				{Name: "python3-rpm", Epoch: 0, Version: "4.14.1", Release: "9.fc28", Arch: "x86_64", SrcName: "rpm", SrcEpoch: 0, SrcVersion: "4.14.1", SrcRelease: "9.fc28"},
				{Name: "dnf", Epoch: 0, Version: "2.7.5", Release: "12.fc28", Arch: "noarch", SrcName: "dnf", SrcEpoch: 0, SrcVersion: "2.7.5", SrcRelease: "12.fc28"},
				{Name: "deltarpm", Epoch: 0, Version: "3.6", Release: "25.fc28", Arch: "x86_64", SrcName: "deltarpm", SrcEpoch: 0, SrcVersion: "3.6", SrcRelease: "25.fc28"},
				{Name: "sssd-client", Epoch: 0, Version: "1.16.3", Release: "2.fc28", Arch: "x86_64", SrcName: "sssd", SrcEpoch: 0, SrcVersion: "1.16.3", SrcRelease: "2.fc28"},
				{Name: "cracklib-dicts", Epoch: 0, Version: "2.9.6", Release: "13.fc28", Arch: "x86_64", SrcName: "cracklib", SrcEpoch: 0, SrcVersion: "2.9.6", SrcRelease: "13.fc28"},
				{Name: "tar", Epoch: 2, Version: "1.30", Release: "3.fc28", Arch: "x86_64", SrcName: "tar", SrcEpoch: 2, SrcVersion: "1.30", SrcRelease: "3.fc28"},
				{Name: "diffutils", Epoch: 0, Version: "3.6", Release: "4.fc28", Arch: "x86_64", SrcName: "diffutils", SrcEpoch: 0, SrcVersion: "3.6", SrcRelease: "4.fc28"},
				{Name: "langpacks-en", Epoch: 0, Version: "1.0", Release: "12.fc28", Arch: "noarch", SrcName: "langpacks", SrcEpoch: 0, SrcVersion: "1.0", SrcRelease: "12.fc28"},
				{Name: "gpg-pubkey", Epoch: 0, Version: "9db62fb1", Release: "59920156", Arch: "None", SrcName: "", SrcEpoch: 0, SrcVersion: "", SrcRelease: ""},
				{Name: "libgcc", Epoch: 0, Version: "8.1.1", Release: "5.fc28", Arch: "x86_64", SrcName: "gcc", SrcEpoch: 0, SrcVersion: "8.1.1", SrcRelease: "5.fc28"},
				{Name: "pkgconf-m4", Epoch: 0, Version: "1.4.2", Release: "1.fc28", Arch: "noarch", SrcName: "pkgconf", SrcEpoch: 0, SrcVersion: "1.4.2", SrcRelease: "1.fc28"},
				{Name: "dnf-conf", Epoch: 0, Version: "2.7.5", Release: "12.fc28", Arch: "noarch", SrcName: "dnf", SrcEpoch: 0, SrcVersion: "2.7.5", SrcRelease: "12.fc28"},
				{Name: "fedora-repos", Epoch: 0, Version: "28", Release: "5", Arch: "noarch", SrcName: "fedora-repos", SrcEpoch: 0, SrcVersion: "28", SrcRelease: "5"},
				{Name: "setup", Epoch: 0, Version: "2.11.4", Release: "1.fc28", Arch: "noarch", SrcName: "setup", SrcEpoch: 0, SrcVersion: "2.11.4", SrcRelease: "1.fc28"},
				{Name: "basesystem", Epoch: 0, Version: "11", Release: "5.fc28", Arch: "noarch", SrcName: "basesystem", SrcEpoch: 0, SrcVersion: "11", SrcRelease: "5.fc28"},
				{Name: "ncurses-base", Epoch: 0, Version: "6.1", Release: "5.20180224.fc28", Arch: "noarch", SrcName: "ncurses", SrcEpoch: 0, SrcVersion: "6.1", SrcRelease: "5.20180224.fc28"},
				{Name: "libselinux", Epoch: 0, Version: "2.8", Release: "1.fc28", Arch: "x86_64", SrcName: "libselinux", SrcEpoch: 0, SrcVersion: "2.8", SrcRelease: "1.fc28"},
				{Name: "ncurses-libs", Epoch: 0, Version: "6.1", Release: "5.20180224.fc28", Arch: "x86_64", SrcName: "ncurses", SrcEpoch: 0, SrcVersion: "6.1", SrcRelease: "5.20180224.fc28"},
				{Name: "glibc", Epoch: 0, Version: "2.27", Release: "32.fc28", Arch: "x86_64", SrcName: "glibc", SrcEpoch: 0, SrcVersion: "2.27", SrcRelease: "32.fc28"},
				{Name: "libsepol", Epoch: 0, Version: "2.8", Release: "1.fc28", Arch: "x86_64", SrcName: "libsepol", SrcEpoch: 0, SrcVersion: "2.8", SrcRelease: "1.fc28"},
				{Name: "xz-libs", Epoch: 0, Version: "5.2.4", Release: "2.fc28", Arch: "x86_64", SrcName: "xz", SrcEpoch: 0, SrcVersion: "5.2.4", SrcRelease: "2.fc28"},
				{Name: "info", Epoch: 0, Version: "6.5", Release: "4.fc28", Arch: "x86_64", SrcName: "texinfo", SrcEpoch: 0, SrcVersion: "6.5", SrcRelease: "4.fc28"},
				{Name: "libdb", Epoch: 0, Version: "5.3.28", Release: "30.fc28", Arch: "x86_64", SrcName: "libdb", SrcEpoch: 0, SrcVersion: "5.3.28", SrcRelease: "30.fc28"},
				{Name: "elfutils-libelf", Epoch: 0, Version: "0.173", Release: "1.fc28", Arch: "x86_64", SrcName: "elfutils", SrcEpoch: 0, SrcVersion: "0.173", SrcRelease: "1.fc28"},
				{Name: "popt", Epoch: 0, Version: "1.16", Release: "14.fc28", Arch: "x86_64", SrcName: "popt", SrcEpoch: 0, SrcVersion: "1.16", SrcRelease: "14.fc28"},
				{Name: "nspr", Epoch: 0, Version: "4.19.0", Release: "1.fc28", Arch: "x86_64", SrcName: "nspr", SrcEpoch: 0, SrcVersion: "4.19.0", SrcRelease: "1.fc28"},
				{Name: "libxcrypt", Epoch: 0, Version: "4.1.2", Release: "1.fc28", Arch: "x86_64", SrcName: "libxcrypt", SrcEpoch: 0, SrcVersion: "4.1.2", SrcRelease: "1.fc28"},
				{Name: "lua-libs", Epoch: 0, Version: "5.3.4", Release: "10.fc28", Arch: "x86_64", SrcName: "lua", SrcEpoch: 0, SrcVersion: "5.3.4", SrcRelease: "10.fc28"},
				{Name: "libuuid", Epoch: 0, Version: "2.32.1", Release: "1.fc28", Arch: "x86_64", SrcName: "util-linux", SrcEpoch: 0, SrcVersion: "2.32.1", SrcRelease: "1.fc28"},
				{Name: "readline", Epoch: 0, Version: "7.0", Release: "11.fc28", Arch: "x86_64", SrcName: "readline", SrcEpoch: 0, SrcVersion: "7.0", SrcRelease: "11.fc28"},
				{Name: "libattr", Epoch: 0, Version: "2.4.48", Release: "3.fc28", Arch: "x86_64", SrcName: "attr", SrcEpoch: 0, SrcVersion: "2.4.48", SrcRelease: "3.fc28"},
				{Name: "coreutils-single", Epoch: 0, Version: "8.29", Release: "7.fc28", Arch: "x86_64", SrcName: "coreutils", SrcEpoch: 0, SrcVersion: "8.29", SrcRelease: "7.fc28"},
				{Name: "libblkid", Epoch: 0, Version: "2.32.1", Release: "1.fc28", Arch: "x86_64", SrcName: "util-linux", SrcEpoch: 0, SrcVersion: "2.32.1", SrcRelease: "1.fc28"},
				{Name: "gmp", Epoch: 1, Version: "6.1.2", Release: "7.fc28", Arch: "x86_64", SrcName: "gmp", SrcEpoch: 1, SrcVersion: "6.1.2", SrcRelease: "7.fc28"},
				{Name: "libunistring", Epoch: 0, Version: "0.9.10", Release: "1.fc28", Arch: "x86_64", SrcName: "libunistring", SrcEpoch: 0, SrcVersion: "0.9.10", SrcRelease: "1.fc28"},
				{Name: "sqlite-libs", Epoch: 0, Version: "3.22.0", Release: "4.fc28", Arch: "x86_64", SrcName: "sqlite", SrcEpoch: 0, SrcVersion: "3.22.0", SrcRelease: "4.fc28"},
				{Name: "audit-libs", Epoch: 0, Version: "2.8.4", Release: "2.fc28", Arch: "x86_64", SrcName: "audit", SrcEpoch: 0, SrcVersion: "2.8.4", SrcRelease: "2.fc28"},
				{Name: "chkconfig", Epoch: 0, Version: "1.10", Release: "4.fc28", Arch: "x86_64", SrcName: "chkconfig", SrcEpoch: 0, SrcVersion: "1.10", SrcRelease: "4.fc28"},
				{Name: "libsmartcols", Epoch: 0, Version: "2.32.1", Release: "1.fc28", Arch: "x86_64", SrcName: "util-linux", SrcEpoch: 0, SrcVersion: "2.32.1", SrcRelease: "1.fc28"},
				{Name: "pcre", Epoch: 0, Version: "8.42", Release: "3.fc28", Arch: "x86_64", SrcName: "pcre", SrcEpoch: 0, SrcVersion: "8.42", SrcRelease: "3.fc28"},
				{Name: "grep", Epoch: 0, Version: "3.1", Release: "5.fc28", Arch: "x86_64", SrcName: "grep", SrcEpoch: 0, SrcVersion: "3.1", SrcRelease: "5.fc28"},
				{Name: "crypto-policies", Epoch: 0, Version: "20180425", Release: "5.git6ad4018.fc28", Arch: "noarch", SrcName: "crypto-policies", SrcEpoch: 0, SrcVersion: "20180425", SrcRelease: "5.git6ad4018.fc28"},
				{Name: "gdbm-libs", Epoch: 1, Version: "1.14.1", Release: "4.fc28", Arch: "x86_64", SrcName: "gdbm", SrcEpoch: 1, SrcVersion: "1.14.1", SrcRelease: "4.fc28"},
				{Name: "p11-kit-trust", Epoch: 0, Version: "0.23.12", Release: "1.fc28", Arch: "x86_64", SrcName: "p11-kit", SrcEpoch: 0, SrcVersion: "0.23.12", SrcRelease: "1.fc28"},
				{Name: "openssl-libs", Epoch: 1, Version: "1.1.0h", Release: "3.fc28", Arch: "x86_64", SrcName: "openssl", SrcEpoch: 1, SrcVersion: "1.1.0h", SrcRelease: "3.fc28"},
				{Name: "ima-evm-utils", Epoch: 0, Version: "1.1", Release: "2.fc28", Arch: "x86_64", SrcName: "ima-evm-utils", SrcEpoch: 0, SrcVersion: "1.1", SrcRelease: "2.fc28"},
				{Name: "gdbm", Epoch: 1, Version: "1.14.1", Release: "4.fc28", Arch: "x86_64", SrcName: "gdbm", SrcEpoch: 1, SrcVersion: "1.14.1", SrcRelease: "4.fc28"},
				{Name: "gobject-introspection", Epoch: 0, Version: "1.56.1", Release: "1.fc28", Arch: "x86_64", SrcName: "gobject-introspection", SrcEpoch: 0, SrcVersion: "1.56.1", SrcRelease: "1.fc28"},
				{Name: "shadow-utils", Epoch: 2, Version: "4.6", Release: "1.fc28", Arch: "x86_64", SrcName: "shadow-utils", SrcEpoch: 2, SrcVersion: "4.6", SrcRelease: "1.fc28"},
				{Name: "libpsl", Epoch: 0, Version: "0.20.2", Release: "2.fc28", Arch: "x86_64", SrcName: "libpsl", SrcEpoch: 0, SrcVersion: "0.20.2", SrcRelease: "2.fc28"},
				{Name: "nettle", Epoch: 0, Version: "3.4", Release: "2.fc28", Arch: "x86_64", SrcName: "nettle", SrcEpoch: 0, SrcVersion: "3.4", SrcRelease: "2.fc28"},
				{Name: "libfdisk", Epoch: 0, Version: "2.32.1", Release: "1.fc28", Arch: "x86_64", SrcName: "util-linux", SrcEpoch: 0, SrcVersion: "2.32.1", SrcRelease: "1.fc28"},
				{Name: "cracklib", Epoch: 0, Version: "2.9.6", Release: "13.fc28", Arch: "x86_64", SrcName: "cracklib", SrcEpoch: 0, SrcVersion: "2.9.6", SrcRelease: "13.fc28"},
				{Name: "libcomps", Epoch: 0, Version: "0.1.8", Release: "11.fc28", Arch: "x86_64", SrcName: "libcomps", SrcEpoch: 0, SrcVersion: "0.1.8", SrcRelease: "11.fc28"},
				{Name: "nss-softokn", Epoch: 0, Version: "3.38.0", Release: "1.0.fc28", Arch: "x86_64", SrcName: "nss-softokn", SrcEpoch: 0, SrcVersion: "3.38.0", SrcRelease: "1.0.fc28"},
				{Name: "nss-sysinit", Epoch: 0, Version: "3.38.0", Release: "1.0.fc28", Arch: "x86_64", SrcName: "nss", SrcEpoch: 0, SrcVersion: "3.38.0", SrcRelease: "1.0.fc28"},
				{Name: "libksba", Epoch: 0, Version: "1.3.5", Release: "7.fc28", Arch: "x86_64", SrcName: "libksba", SrcEpoch: 0, SrcVersion: "1.3.5", SrcRelease: "7.fc28"},
				{Name: "kmod-libs", Epoch: 0, Version: "25", Release: "2.fc28", Arch: "x86_64", SrcName: "kmod", SrcEpoch: 0, SrcVersion: "25", SrcRelease: "2.fc28"},
				{Name: "libsss_nss_idmap", Epoch: 0, Version: "1.16.3", Release: "2.fc28", Arch: "x86_64", SrcName: "sssd", SrcEpoch: 0, SrcVersion: "1.16.3", SrcRelease: "2.fc28"},
				{Name: "libverto", Epoch: 0, Version: "0.3.0", Release: "5.fc28", Arch: "x86_64", SrcName: "libverto", SrcEpoch: 0, SrcVersion: "0.3.0", SrcRelease: "5.fc28"},
				{Name: "gawk", Epoch: 0, Version: "4.2.1", Release: "1.fc28", Arch: "x86_64", SrcName: "gawk", SrcEpoch: 0, SrcVersion: "4.2.1", SrcRelease: "1.fc28"},
				{Name: "libtirpc", Epoch: 0, Version: "1.0.3", Release: "3.rc2.fc28", Arch: "x86_64", SrcName: "libtirpc", SrcEpoch: 0, SrcVersion: "1.0.3", SrcRelease: "3.rc2.fc28"},
				{Name: "python3-libs", Epoch: 0, Version: "3.6.6", Release: "1.fc28", Arch: "x86_64", SrcName: "python3", SrcEpoch: 0, SrcVersion: "3.6.6", SrcRelease: "1.fc28"},
				{Name: "python3-setuptools", Epoch: 0, Version: "39.2.0", Release: "6.fc28", Arch: "noarch", SrcName: "python-setuptools", SrcEpoch: 0, SrcVersion: "39.2.0", SrcRelease: "6.fc28"},
				{Name: "libpwquality", Epoch: 0, Version: "1.4.0", Release: "7.fc28", Arch: "x86_64", SrcName: "libpwquality", SrcEpoch: 0, SrcVersion: "1.4.0", SrcRelease: "7.fc28"},
				{Name: "util-linux", Epoch: 0, Version: "2.32.1", Release: "1.fc28", Arch: "x86_64", SrcName: "util-linux", SrcEpoch: 0, SrcVersion: "2.32.1", SrcRelease: "1.fc28"},
				{Name: "python3-libcomps", Epoch: 0, Version: "0.1.8", Release: "11.fc28", Arch: "x86_64", SrcName: "libcomps", SrcEpoch: 0, SrcVersion: "0.1.8", SrcRelease: "11.fc28"},
				{Name: "python3-six", Epoch: 0, Version: "1.11.0", Release: "3.fc28", Arch: "noarch", SrcName: "python-six", SrcEpoch: 0, SrcVersion: "1.11.0", SrcRelease: "3.fc28"},
				{Name: "cyrus-sasl-lib", Epoch: 0, Version: "2.1.27", Release: "0.2rc7.fc28", Arch: "x86_64", SrcName: "cyrus-sasl", SrcEpoch: 0, SrcVersion: "2.1.27", SrcRelease: "0.2rc7.fc28"},
				{Name: "libssh", Epoch: 0, Version: "0.8.2", Release: "1.fc28", Arch: "x86_64", SrcName: "libssh", SrcEpoch: 0, SrcVersion: "0.8.2", SrcRelease: "1.fc28"},
				{Name: "qrencode-libs", Epoch: 0, Version: "3.4.4", Release: "5.fc28", Arch: "x86_64", SrcName: "qrencode", SrcEpoch: 0, SrcVersion: "3.4.4", SrcRelease: "5.fc28"},
				{Name: "gnupg2", Epoch: 0, Version: "2.2.8", Release: "1.fc28", Arch: "x86_64", SrcName: "gnupg2", SrcEpoch: 0, SrcVersion: "2.2.8", SrcRelease: "1.fc28"},
				{Name: "python3-gpg", Epoch: 0, Version: "1.10.0", Release: "4.fc28", Arch: "x86_64", SrcName: "gpgme", SrcEpoch: 0, SrcVersion: "1.10.0", SrcRelease: "4.fc28"},
				{Name: "libargon2", Epoch: 0, Version: "20161029", Release: "5.fc28", Arch: "x86_64", SrcName: "argon2", SrcEpoch: 0, SrcVersion: "20161029", SrcRelease: "5.fc28"},
				{Name: "libmodulemd", Epoch: 0, Version: "1.6.2", Release: "2.fc28", Arch: "x86_64", SrcName: "libmodulemd", SrcEpoch: 0, SrcVersion: "1.6.2", SrcRelease: "2.fc28"},
				{Name: "pkgconf", Epoch: 0, Version: "1.4.2", Release: "1.fc28", Arch: "x86_64", SrcName: "pkgconf", SrcEpoch: 0, SrcVersion: "1.4.2", SrcRelease: "1.fc28"},
				{Name: "libpcap", Epoch: 14, Version: "1.9.0", Release: "1.fc28", Arch: "x86_64", SrcName: "libpcap", SrcEpoch: 14, SrcVersion: "1.9.0", SrcRelease: "1.fc28"},
				{Name: "device-mapper", Epoch: 0, Version: "1.02.146", Release: "5.fc28", Arch: "x86_64", SrcName: "lvm2", SrcEpoch: 0, SrcVersion: "2.02.177", SrcRelease: "5.fc28"},
				{Name: "cryptsetup-libs", Epoch: 0, Version: "2.0.4", Release: "1.fc28", Arch: "x86_64", SrcName: "cryptsetup", SrcEpoch: 0, SrcVersion: "2.0.4", SrcRelease: "1.fc28"},
				{Name: "elfutils-libs", Epoch: 0, Version: "0.173", Release: "1.fc28", Arch: "x86_64", SrcName: "elfutils", SrcEpoch: 0, SrcVersion: "0.173", SrcRelease: "1.fc28"},
				{Name: "dbus", Epoch: 1, Version: "1.12.10", Release: "1.fc28", Arch: "x86_64", SrcName: "dbus", SrcEpoch: 1, SrcVersion: "1.12.10", SrcRelease: "1.fc28"},
				{Name: "libnghttp2", Epoch: 0, Version: "1.32.1", Release: "1.fc28", Arch: "x86_64", SrcName: "nghttp2", SrcEpoch: 0, SrcVersion: "1.32.1", SrcRelease: "1.fc28"},
				{Name: "librepo", Epoch: 0, Version: "1.8.1", Release: "7.fc28", Arch: "x86_64", SrcName: "librepo", SrcEpoch: 0, SrcVersion: "1.8.1", SrcRelease: "7.fc28"},
				{Name: "curl", Epoch: 0, Version: "7.59.0", Release: "6.fc28", Arch: "x86_64", SrcName: "curl", SrcEpoch: 0, SrcVersion: "7.59.0", SrcRelease: "6.fc28"},
				{Name: "rpm-libs", Epoch: 0, Version: "4.14.1", Release: "9.fc28", Arch: "x86_64", SrcName: "rpm", SrcEpoch: 0, SrcVersion: "4.14.1", SrcRelease: "9.fc28"},
				{Name: "libsolv", Epoch: 0, Version: "0.6.35", Release: "1.fc28", Arch: "x86_64", SrcName: "libsolv", SrcEpoch: 0, SrcVersion: "0.6.35", SrcRelease: "1.fc28"},
				{Name: "python3-hawkey", Epoch: 0, Version: "0.11.1", Release: "3.fc28", Arch: "x86_64", SrcName: "libdnf", SrcEpoch: 0, SrcVersion: "0.11.1", SrcRelease: "3.fc28"},
				{Name: "rpm-sign-libs", Epoch: 0, Version: "4.14.1", Release: "9.fc28", Arch: "x86_64", SrcName: "rpm", SrcEpoch: 0, SrcVersion: "4.14.1", SrcRelease: "9.fc28"},
				{Name: "python3-dnf", Epoch: 0, Version: "2.7.5", Release: "12.fc28", Arch: "noarch", SrcName: "dnf", SrcEpoch: 0, SrcVersion: "2.7.5", SrcRelease: "12.fc28"},
				{Name: "dnf-yum", Epoch: 0, Version: "2.7.5", Release: "12.fc28", Arch: "noarch", SrcName: "dnf", SrcEpoch: 0, SrcVersion: "2.7.5", SrcRelease: "12.fc28"},
				{Name: "rpm-plugin-systemd-inhibit", Epoch: 0, Version: "4.14.1", Release: "9.fc28", Arch: "x86_64", SrcName: "rpm", SrcEpoch: 0, SrcVersion: "4.14.1", SrcRelease: "9.fc28"},
				{Name: "nss-tools", Epoch: 0, Version: "3.38.0", Release: "1.0.fc28", Arch: "x86_64", SrcName: "nss", SrcEpoch: 0, SrcVersion: "3.38.0", SrcRelease: "1.0.fc28"},
				{Name: "openssl-pkcs11", Epoch: 0, Version: "0.4.8", Release: "1.fc28", Arch: "x86_64", SrcName: "openssl-pkcs11", SrcEpoch: 0, SrcVersion: "0.4.8", SrcRelease: "1.fc28"},
				{Name: "vim-minimal", Epoch: 2, Version: "8.1.328", Release: "1.fc28", Arch: "x86_64", SrcName: "vim", SrcEpoch: 2, SrcVersion: "8.1.328", SrcRelease: "1.fc28"},
				{Name: "glibc-langpack-en", Epoch: 0, Version: "2.27", Release: "32.fc28", Arch: "x86_64", SrcName: "glibc", SrcEpoch: 0, SrcVersion: "2.27", SrcRelease: "32.fc28"},
				{Name: "rootfiles", Epoch: 0, Version: "8.1", Release: "22.fc28", Arch: "noarch", SrcName: "rootfiles", SrcEpoch: 0, SrcVersion: "8.1", SrcRelease: "22.fc28"},
			},
		},
	}
	a := rpmPkgAnalyzer{}
	for testname, tc := range tests {
		t.Run(testname, func(t *testing.T) {
			bytes, err := ioutil.ReadFile(tc.path)
			require.NoError(t, err)

			pkgs, err := a.parsePkgInfo(bytes)
			require.NoError(t, err)

			sort.Slice(tc.pkgs, func(i, j int) bool {
				return tc.pkgs[i].Name < tc.pkgs[j].Name
			})
			sort.Slice(pkgs, func(i, j int) bool {
				return pkgs[i].Name < pkgs[j].Name
			})

			assert.Equal(t, tc.pkgs, pkgs)
		})
	}
}
