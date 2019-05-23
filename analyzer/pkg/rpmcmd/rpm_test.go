package rpmcmd

import (
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/knqyf263/fanal/analyzer"
)

func TestParseRpmInfo(t *testing.T) {
	var tests = map[string]struct {
		path string
		pkgs []analyzer.Package
	}{
		"Valid": {
			path: "./testdata/valid",
			pkgs: []analyzer.Package{
				{Name: "centos-release", Version: "7", Release: "1.1503.el7.centos.2.8", Epoch: 0, SrcName: "centos-release", SrcVersion: "7", SrcRelease: "1.1503.el7.centos.2.8", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "filesystem", Version: "3.2", Release: "18.el7", Epoch: 0, SrcName: "filesystem", SrcVersion: "3.2", SrcRelease: "18.el7", SrcEpoch: 0, Arch: "x86_64"},
			},
		},
		"ValidBig": {
			path: "./testdata/valid_big",
			pkgs: []analyzer.Package{
				{Name: "publicsuffix-list-dafsa", Version: "20180514", Release: "1.fc28", Epoch: 0, SrcName: "publicsuffix-list", SrcVersion: "20180514", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "libreport-filesystem", Version: "2.9.5", Release: "1.fc28", Epoch: 0, SrcName: "libreport", SrcVersion: "2.9.5", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "fedora-gpg-keys", Version: "28", Release: "5", Epoch: 0, SrcName: "fedora-repos", SrcVersion: "28", SrcRelease: "5", SrcEpoch: 0, Arch: "noarch"},
				{Name: "fedora-release", Version: "28", Release: "2", Epoch: 0, SrcName: "fedora-release", SrcVersion: "28", SrcRelease: "2", SrcEpoch: 0, Arch: "noarch"},
				{Name: "filesystem", Version: "3.8", Release: "2.fc28", Epoch: 0, SrcName: "filesystem", SrcVersion: "3.8", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "tzdata", Version: "2018e", Release: "1.fc28", Epoch: 0, SrcName: "tzdata", SrcVersion: "2018e", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "pcre2", Version: "10.31", Release: "10.fc28", Epoch: 0, SrcName: "pcre2", SrcVersion: "10.31", SrcRelease: "10.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "glibc-minimal-langpack", Version: "2.27", Release: "32.fc28", Epoch: 0, SrcName: "glibc", SrcVersion: "2.27", SrcRelease: "32.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "glibc-common", Version: "2.27", Release: "32.fc28", Epoch: 0, SrcName: "glibc", SrcVersion: "2.27", SrcRelease: "32.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "bash", Version: "4.4.23", Release: "1.fc28", Epoch: 0, SrcName: "bash", SrcVersion: "4.4.23", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "zlib", Version: "1.2.11", Release: "8.fc28", Epoch: 0, SrcName: "zlib", SrcVersion: "1.2.11", SrcRelease: "8.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "bzip2-libs", Version: "1.0.6", Release: "26.fc28", Epoch: 0, SrcName: "bzip2", SrcVersion: "1.0.6", SrcRelease: "26.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libcap", Version: "2.25", Release: "9.fc28", Epoch: 0, SrcName: "libcap", SrcVersion: "2.25", SrcRelease: "9.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libgpg-error", Version: "1.31", Release: "1.fc28", Epoch: 0, SrcName: "libgpg-error", SrcVersion: "1.31", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libzstd", Version: "1.3.5", Release: "1.fc28", Epoch: 0, SrcName: "zstd", SrcVersion: "1.3.5", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "expat", Version: "2.2.5", Release: "3.fc28", Epoch: 0, SrcName: "expat", SrcVersion: "2.2.5", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "nss-util", Version: "3.38.0", Release: "1.0.fc28", Epoch: 0, SrcName: "nss-util", SrcVersion: "3.38.0", SrcRelease: "1.0.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libcom_err", Version: "1.44.2", Release: "0.fc28", Epoch: 0, SrcName: "e2fsprogs", SrcVersion: "1.44.2", SrcRelease: "0.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libffi", Version: "3.1", Release: "16.fc28", Epoch: 0, SrcName: "libffi", SrcVersion: "3.1", SrcRelease: "16.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libgcrypt", Version: "1.8.3", Release: "1.fc28", Epoch: 0, SrcName: "libgcrypt", SrcVersion: "1.8.3", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libxml2", Version: "2.9.8", Release: "4.fc28", Epoch: 0, SrcName: "libxml2", SrcVersion: "2.9.8", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libacl", Version: "2.2.53", Release: "1.fc28", Epoch: 0, SrcName: "acl", SrcVersion: "2.2.53", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "sed", Version: "4.5", Release: "1.fc28", Epoch: 0, SrcName: "sed", SrcVersion: "4.5", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libmount", Version: "2.32.1", Release: "1.fc28", Epoch: 0, SrcName: "util-linux", SrcVersion: "2.32.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "p11-kit", Version: "0.23.12", Release: "1.fc28", Epoch: 0, SrcName: "p11-kit", SrcVersion: "0.23.12", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libidn2", Version: "2.0.5", Release: "1.fc28", Epoch: 0, SrcName: "libidn2", SrcVersion: "2.0.5", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libcap-ng", Version: "0.7.9", Release: "4.fc28", Epoch: 0, SrcName: "libcap-ng", SrcVersion: "0.7.9", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "lz4-libs", Version: "1.8.1.2", Release: "4.fc28", Epoch: 0, SrcName: "lz4", SrcVersion: "1.8.1.2", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libassuan", Version: "2.5.1", Release: "3.fc28", Epoch: 0, SrcName: "libassuan", SrcVersion: "2.5.1", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "keyutils-libs", Version: "1.5.10", Release: "6.fc28", Epoch: 0, SrcName: "keyutils", SrcVersion: "1.5.10", SrcRelease: "6.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "glib2", Version: "2.56.1", Release: "4.fc28", Epoch: 0, SrcName: "glib2", SrcVersion: "2.56.1", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "systemd-libs", Version: "238", Release: "9.git0e0aa59.fc28", Epoch: 0, SrcName: "systemd", SrcVersion: "238", SrcRelease: "9.git0e0aa59.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "dbus-libs", Version: "1.12.10", Release: "1.fc28", Epoch: 1, SrcName: "dbus", SrcVersion: "1.12.10", SrcRelease: "1.fc28", SrcEpoch: 1, Arch: "x86_64"},
				{Name: "libtasn1", Version: "4.13", Release: "2.fc28", Epoch: 0, SrcName: "libtasn1", SrcVersion: "4.13", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "ca-certificates", Version: "2018.2.24", Release: "1.0.fc28", Epoch: 0, SrcName: "ca-certificates", SrcVersion: "2018.2.24", SrcRelease: "1.0.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "libarchive", Version: "3.3.1", Release: "4.fc28", Epoch: 0, SrcName: "libarchive", SrcVersion: "3.3.1", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "openssl", Version: "1.1.0h", Release: "3.fc28", Epoch: 1, SrcName: "openssl", SrcVersion: "1.1.0h", SrcRelease: "3.fc28", SrcEpoch: 1, Arch: "x86_64"},
				{Name: "libusbx", Version: "1.0.22", Release: "1.fc28", Epoch: 0, SrcName: "libusbx", SrcVersion: "1.0.22", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libsemanage", Version: "2.8", Release: "2.fc28", Epoch: 0, SrcName: "libsemanage", SrcVersion: "2.8", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libutempter", Version: "1.1.6", Release: "14.fc28", Epoch: 0, SrcName: "libutempter", SrcVersion: "1.1.6", SrcRelease: "14.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "mpfr", Version: "3.1.6", Release: "1.fc28", Epoch: 0, SrcName: "mpfr", SrcVersion: "3.1.6", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "gnutls", Version: "3.6.3", Release: "4.fc28", Epoch: 0, SrcName: "gnutls", SrcVersion: "3.6.3", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "gzip", Version: "1.9", Release: "3.fc28", Epoch: 0, SrcName: "gzip", SrcVersion: "1.9", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "acl", Version: "2.2.53", Release: "1.fc28", Epoch: 0, SrcName: "acl", SrcVersion: "2.2.53", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "nss-softokn-freebl", Version: "3.38.0", Release: "1.0.fc28", Epoch: 0, SrcName: "nss-softokn", SrcVersion: "3.38.0", SrcRelease: "1.0.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "nss", Version: "3.38.0", Release: "1.0.fc28", Epoch: 0, SrcName: "nss", SrcVersion: "3.38.0", SrcRelease: "1.0.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libmetalink", Version: "0.1.3", Release: "6.fc28", Epoch: 0, SrcName: "libmetalink", SrcVersion: "0.1.3", SrcRelease: "6.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libdb-utils", Version: "5.3.28", Release: "30.fc28", Epoch: 0, SrcName: "libdb", SrcVersion: "5.3.28", SrcRelease: "30.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "file-libs", Version: "5.33", Release: "7.fc28", Epoch: 0, SrcName: "file", SrcVersion: "5.33", SrcRelease: "7.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libsss_idmap", Version: "1.16.3", Release: "2.fc28", Epoch: 0, SrcName: "sssd", SrcVersion: "1.16.3", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libsigsegv", Version: "2.11", Release: "5.fc28", Epoch: 0, SrcName: "libsigsegv", SrcVersion: "2.11", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "krb5-libs", Version: "1.16.1", Release: "13.fc28", Epoch: 0, SrcName: "krb5", SrcVersion: "1.16.1", SrcRelease: "13.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libnsl2", Version: "1.2.0", Release: "2.20180605git4a062cf.fc28", Epoch: 0, SrcName: "libnsl2", SrcVersion: "1.2.0", SrcRelease: "2.20180605git4a062cf.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-pip", Version: "9.0.3", Release: "2.fc28", Epoch: 0, SrcName: "python-pip", SrcVersion: "9.0.3", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "python3", Version: "3.6.6", Release: "1.fc28", Epoch: 0, SrcName: "python3", SrcVersion: "3.6.6", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "pam", Version: "1.3.1", Release: "1.fc28", Epoch: 0, SrcName: "pam", SrcVersion: "1.3.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-gobject-base", Version: "3.28.3", Release: "1.fc28", Epoch: 0, SrcName: "pygobject3", SrcVersion: "3.28.3", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-smartcols", Version: "0.3.0", Release: "2.fc28", Epoch: 0, SrcName: "python-smartcols", SrcVersion: "0.3.0", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-iniparse", Version: "0.4", Release: "30.fc28", Epoch: 0, SrcName: "python-iniparse", SrcVersion: "0.4", SrcRelease: "30.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "openldap", Version: "2.4.46", Release: "3.fc28", Epoch: 0, SrcName: "openldap", SrcVersion: "2.4.46", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libseccomp", Version: "2.3.3", Release: "2.fc28", Epoch: 0, SrcName: "libseccomp", SrcVersion: "2.3.3", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "npth", Version: "1.5", Release: "4.fc28", Epoch: 0, SrcName: "npth", SrcVersion: "1.5", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "gpgme", Version: "1.10.0", Release: "4.fc28", Epoch: 0, SrcName: "gpgme", SrcVersion: "1.10.0", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "json-c", Version: "0.13.1", Release: "2.fc28", Epoch: 0, SrcName: "json-c", SrcVersion: "0.13.1", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libyaml", Version: "0.1.7", Release: "5.fc28", Epoch: 0, SrcName: "libyaml", SrcVersion: "0.1.7", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libpkgconf", Version: "1.4.2", Release: "1.fc28", Epoch: 0, SrcName: "pkgconf", SrcVersion: "1.4.2", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "pkgconf-pkg-config", Version: "1.4.2", Release: "1.fc28", Epoch: 0, SrcName: "pkgconf", SrcVersion: "1.4.2", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "iptables-libs", Version: "1.6.2", Release: "3.fc28", Epoch: 0, SrcName: "iptables", SrcVersion: "1.6.2", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "device-mapper-libs", Version: "1.02.146", Release: "5.fc28", Epoch: 0, SrcName: "lvm2", SrcVersion: "2.02.177", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "systemd-pam", Version: "238", Release: "9.git0e0aa59.fc28", Epoch: 0, SrcName: "systemd", SrcVersion: "238", SrcRelease: "9.git0e0aa59.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "systemd", Version: "238", Release: "9.git0e0aa59.fc28", Epoch: 0, SrcName: "systemd", SrcVersion: "238", SrcRelease: "9.git0e0aa59.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "elfutils-default-yama-scope", Version: "0.173", Release: "1.fc28", Epoch: 0, SrcName: "elfutils", SrcVersion: "0.173", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "libcurl", Version: "7.59.0", Release: "6.fc28", Epoch: 0, SrcName: "curl", SrcVersion: "7.59.0", SrcRelease: "6.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-librepo", Version: "1.8.1", Release: "7.fc28", Epoch: 0, SrcName: "librepo", SrcVersion: "1.8.1", SrcRelease: "7.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "rpm-plugin-selinux", Version: "4.14.1", Release: "9.fc28", Epoch: 0, SrcName: "rpm", SrcVersion: "4.14.1", SrcRelease: "9.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "rpm", Version: "4.14.1", Release: "9.fc28", Epoch: 0, SrcName: "rpm", SrcVersion: "4.14.1", SrcRelease: "9.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libdnf", Version: "0.11.1", Release: "3.fc28", Epoch: 0, SrcName: "libdnf", SrcVersion: "0.11.1", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "rpm-build-libs", Version: "4.14.1", Release: "9.fc28", Epoch: 0, SrcName: "rpm", SrcVersion: "4.14.1", SrcRelease: "9.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-rpm", Version: "4.14.1", Release: "9.fc28", Epoch: 0, SrcName: "rpm", SrcVersion: "4.14.1", SrcRelease: "9.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "dnf", Version: "2.7.5", Release: "12.fc28", Epoch: 0, SrcName: "dnf", SrcVersion: "2.7.5", SrcRelease: "12.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "deltarpm", Version: "3.6", Release: "25.fc28", Epoch: 0, SrcName: "deltarpm", SrcVersion: "3.6", SrcRelease: "25.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "sssd-client", Version: "1.16.3", Release: "2.fc28", Epoch: 0, SrcName: "sssd", SrcVersion: "1.16.3", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "cracklib-dicts", Version: "2.9.6", Release: "13.fc28", Epoch: 0, SrcName: "cracklib", SrcVersion: "2.9.6", SrcRelease: "13.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "tar", Version: "1.30", Release: "3.fc28", Epoch: 2, SrcName: "tar", SrcVersion: "1.30", SrcRelease: "3.fc28", SrcEpoch: 2, Arch: "x86_64"},
				{Name: "diffutils", Version: "3.6", Release: "4.fc28", Epoch: 0, SrcName: "diffutils", SrcVersion: "3.6", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "langpacks-en", Version: "1.0", Release: "12.fc28", Epoch: 0, SrcName: "langpacks", SrcVersion: "1.0", SrcRelease: "12.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "gpg-pubkey", Version: "9db62fb1", Release: "59920156", Epoch: 0, SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0, Arch: "(none)"},
				{Name: "libgcc", Version: "8.1.1", Release: "5.fc28", Epoch: 0, SrcName: "gcc", SrcVersion: "8.1.1", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "pkgconf-m4", Version: "1.4.2", Release: "1.fc28", Epoch: 0, SrcName: "pkgconf", SrcVersion: "1.4.2", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "dnf-conf", Version: "2.7.5", Release: "12.fc28", Epoch: 0, SrcName: "dnf", SrcVersion: "2.7.5", SrcRelease: "12.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "fedora-repos", Version: "28", Release: "5", Epoch: 0, SrcName: "fedora-repos", SrcVersion: "28", SrcRelease: "5", SrcEpoch: 0, Arch: "noarch"},
				{Name: "setup", Version: "2.11.4", Release: "1.fc28", Epoch: 0, SrcName: "setup", SrcVersion: "2.11.4", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "basesystem", Version: "11", Release: "5.fc28", Epoch: 0, SrcName: "basesystem", SrcVersion: "11", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "ncurses-base", Version: "6.1", Release: "5.20180224.fc28", Epoch: 0, SrcName: "ncurses", SrcVersion: "6.1", SrcRelease: "5.20180224.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "libselinux", Version: "2.8", Release: "1.fc28", Epoch: 0, SrcName: "libselinux", SrcVersion: "2.8", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "ncurses-libs", Version: "6.1", Release: "5.20180224.fc28", Epoch: 0, SrcName: "ncurses", SrcVersion: "6.1", SrcRelease: "5.20180224.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "glibc", Version: "2.27", Release: "32.fc28", Epoch: 0, SrcName: "glibc", SrcVersion: "2.27", SrcRelease: "32.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libsepol", Version: "2.8", Release: "1.fc28", Epoch: 0, SrcName: "libsepol", SrcVersion: "2.8", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "xz-libs", Version: "5.2.4", Release: "2.fc28", Epoch: 0, SrcName: "xz", SrcVersion: "5.2.4", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "info", Version: "6.5", Release: "4.fc28", Epoch: 0, SrcName: "texinfo", SrcVersion: "6.5", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libdb", Version: "5.3.28", Release: "30.fc28", Epoch: 0, SrcName: "libdb", SrcVersion: "5.3.28", SrcRelease: "30.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "elfutils-libelf", Version: "0.173", Release: "1.fc28", Epoch: 0, SrcName: "elfutils", SrcVersion: "0.173", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "popt", Version: "1.16", Release: "14.fc28", Epoch: 0, SrcName: "popt", SrcVersion: "1.16", SrcRelease: "14.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "nspr", Version: "4.19.0", Release: "1.fc28", Epoch: 0, SrcName: "nspr", SrcVersion: "4.19.0", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libxcrypt", Version: "4.1.2", Release: "1.fc28", Epoch: 0, SrcName: "libxcrypt", SrcVersion: "4.1.2", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "lua-libs", Version: "5.3.4", Release: "10.fc28", Epoch: 0, SrcName: "lua", SrcVersion: "5.3.4", SrcRelease: "10.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libuuid", Version: "2.32.1", Release: "1.fc28", Epoch: 0, SrcName: "util-linux", SrcVersion: "2.32.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "readline", Version: "7.0", Release: "11.fc28", Epoch: 0, SrcName: "readline", SrcVersion: "7.0", SrcRelease: "11.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libattr", Version: "2.4.48", Release: "3.fc28", Epoch: 0, SrcName: "attr", SrcVersion: "2.4.48", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "coreutils-single", Version: "8.29", Release: "7.fc28", Epoch: 0, SrcName: "coreutils", SrcVersion: "8.29", SrcRelease: "7.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libblkid", Version: "2.32.1", Release: "1.fc28", Epoch: 0, SrcName: "util-linux", SrcVersion: "2.32.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "gmp", Version: "6.1.2", Release: "7.fc28", Epoch: 1, SrcName: "gmp", SrcVersion: "6.1.2", SrcRelease: "7.fc28", SrcEpoch: 1, Arch: "x86_64"},
				{Name: "libunistring", Version: "0.9.10", Release: "1.fc28", Epoch: 0, SrcName: "libunistring", SrcVersion: "0.9.10", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "sqlite-libs", Version: "3.22.0", Release: "4.fc28", Epoch: 0, SrcName: "sqlite", SrcVersion: "3.22.0", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "audit-libs", Version: "2.8.4", Release: "2.fc28", Epoch: 0, SrcName: "audit", SrcVersion: "2.8.4", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "chkconfig", Version: "1.10", Release: "4.fc28", Epoch: 0, SrcName: "chkconfig", SrcVersion: "1.10", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libsmartcols", Version: "2.32.1", Release: "1.fc28", Epoch: 0, SrcName: "util-linux", SrcVersion: "2.32.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "pcre", Version: "8.42", Release: "3.fc28", Epoch: 0, SrcName: "pcre", SrcVersion: "8.42", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "grep", Version: "3.1", Release: "5.fc28", Epoch: 0, SrcName: "grep", SrcVersion: "3.1", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "crypto-policies", Version: "20180425", Release: "5.git6ad4018.fc28", Epoch: 0, SrcName: "crypto-policies", SrcVersion: "20180425", SrcRelease: "5.git6ad4018.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "gdbm-libs", Version: "1.14.1", Release: "4.fc28", Epoch: 1, SrcName: "gdbm", SrcVersion: "1.14.1", SrcRelease: "4.fc28", SrcEpoch: 1, Arch: "x86_64"},
				{Name: "p11-kit-trust", Version: "0.23.12", Release: "1.fc28", Epoch: 0, SrcName: "p11-kit", SrcVersion: "0.23.12", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "openssl-libs", Version: "1.1.0h", Release: "3.fc28", Epoch: 1, SrcName: "openssl", SrcVersion: "1.1.0h", SrcRelease: "3.fc28", SrcEpoch: 1, Arch: "x86_64"},
				{Name: "ima-evm-utils", Version: "1.1", Release: "2.fc28", Epoch: 0, SrcName: "ima-evm-utils", SrcVersion: "1.1", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "gdbm", Version: "1.14.1", Release: "4.fc28", Epoch: 1, SrcName: "gdbm", SrcVersion: "1.14.1", SrcRelease: "4.fc28", SrcEpoch: 1, Arch: "x86_64"},
				{Name: "gobject-introspection", Version: "1.56.1", Release: "1.fc28", Epoch: 0, SrcName: "gobject-introspection", SrcVersion: "1.56.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "shadow-utils", Version: "4.6", Release: "1.fc28", Epoch: 2, SrcName: "shadow-utils", SrcVersion: "4.6", SrcRelease: "1.fc28", SrcEpoch: 2, Arch: "x86_64"},
				{Name: "libpsl", Version: "0.20.2", Release: "2.fc28", Epoch: 0, SrcName: "libpsl", SrcVersion: "0.20.2", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "nettle", Version: "3.4", Release: "2.fc28", Epoch: 0, SrcName: "nettle", SrcVersion: "3.4", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libfdisk", Version: "2.32.1", Release: "1.fc28", Epoch: 0, SrcName: "util-linux", SrcVersion: "2.32.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "cracklib", Version: "2.9.6", Release: "13.fc28", Epoch: 0, SrcName: "cracklib", SrcVersion: "2.9.6", SrcRelease: "13.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libcomps", Version: "0.1.8", Release: "11.fc28", Epoch: 0, SrcName: "libcomps", SrcVersion: "0.1.8", SrcRelease: "11.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "nss-softokn", Version: "3.38.0", Release: "1.0.fc28", Epoch: 0, SrcName: "nss-softokn", SrcVersion: "3.38.0", SrcRelease: "1.0.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "nss-sysinit", Version: "3.38.0", Release: "1.0.fc28", Epoch: 0, SrcName: "nss", SrcVersion: "3.38.0", SrcRelease: "1.0.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libksba", Version: "1.3.5", Release: "7.fc28", Epoch: 0, SrcName: "libksba", SrcVersion: "1.3.5", SrcRelease: "7.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "kmod-libs", Version: "25", Release: "2.fc28", Epoch: 0, SrcName: "kmod", SrcVersion: "25", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libsss_nss_idmap", Version: "1.16.3", Release: "2.fc28", Epoch: 0, SrcName: "sssd", SrcVersion: "1.16.3", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libverto", Version: "0.3.0", Release: "5.fc28", Epoch: 0, SrcName: "libverto", SrcVersion: "0.3.0", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "gawk", Version: "4.2.1", Release: "1.fc28", Epoch: 0, SrcName: "gawk", SrcVersion: "4.2.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libtirpc", Version: "1.0.3", Release: "3.rc2.fc28", Epoch: 0, SrcName: "libtirpc", SrcVersion: "1.0.3", SrcRelease: "3.rc2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-libs", Version: "3.6.6", Release: "1.fc28", Epoch: 0, SrcName: "python3", SrcVersion: "3.6.6", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-setuptools", Version: "39.2.0", Release: "6.fc28", Epoch: 0, SrcName: "python-setuptools", SrcVersion: "39.2.0", SrcRelease: "6.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "libpwquality", Version: "1.4.0", Release: "7.fc28", Epoch: 0, SrcName: "libpwquality", SrcVersion: "1.4.0", SrcRelease: "7.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "util-linux", Version: "2.32.1", Release: "1.fc28", Epoch: 0, SrcName: "util-linux", SrcVersion: "2.32.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-libcomps", Version: "0.1.8", Release: "11.fc28", Epoch: 0, SrcName: "libcomps", SrcVersion: "0.1.8", SrcRelease: "11.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-six", Version: "1.11.0", Release: "3.fc28", Epoch: 0, SrcName: "python-six", SrcVersion: "1.11.0", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "cyrus-sasl-lib", Version: "2.1.27", Release: "0.2rc7.fc28", Epoch: 0, SrcName: "cyrus-sasl", SrcVersion: "2.1.27", SrcRelease: "0.2rc7.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libssh", Version: "0.8.2", Release: "1.fc28", Epoch: 0, SrcName: "libssh", SrcVersion: "0.8.2", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "qrencode-libs", Version: "3.4.4", Release: "5.fc28", Epoch: 0, SrcName: "qrencode", SrcVersion: "3.4.4", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "gnupg2", Version: "2.2.8", Release: "1.fc28", Epoch: 0, SrcName: "gnupg2", SrcVersion: "2.2.8", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-gpg", Version: "1.10.0", Release: "4.fc28", Epoch: 0, SrcName: "gpgme", SrcVersion: "1.10.0", SrcRelease: "4.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libargon2", Version: "20161029", Release: "5.fc28", Epoch: 0, SrcName: "argon2", SrcVersion: "20161029", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libmodulemd", Version: "1.6.2", Release: "2.fc28", Epoch: 0, SrcName: "libmodulemd", SrcVersion: "1.6.2", SrcRelease: "2.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "pkgconf", Version: "1.4.2", Release: "1.fc28", Epoch: 0, SrcName: "pkgconf", SrcVersion: "1.4.2", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libpcap", Version: "1.9.0", Release: "1.fc28", Epoch: 14, SrcName: "libpcap", SrcVersion: "1.9.0", SrcRelease: "1.fc28", SrcEpoch: 14, Arch: "x86_64"},
				{Name: "device-mapper", Version: "1.02.146", Release: "5.fc28", Epoch: 0, SrcName: "lvm2", SrcVersion: "2.02.177", SrcRelease: "5.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "cryptsetup-libs", Version: "2.0.4", Release: "1.fc28", Epoch: 0, SrcName: "cryptsetup", SrcVersion: "2.0.4", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "elfutils-libs", Version: "0.173", Release: "1.fc28", Epoch: 0, SrcName: "elfutils", SrcVersion: "0.173", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "dbus", Version: "1.12.10", Release: "1.fc28", Epoch: 1, SrcName: "dbus", SrcVersion: "1.12.10", SrcRelease: "1.fc28", SrcEpoch: 1, Arch: "x86_64"},
				{Name: "libnghttp2", Version: "1.32.1", Release: "1.fc28", Epoch: 0, SrcName: "nghttp2", SrcVersion: "1.32.1", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "librepo", Version: "1.8.1", Release: "7.fc28", Epoch: 0, SrcName: "librepo", SrcVersion: "1.8.1", SrcRelease: "7.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "curl", Version: "7.59.0", Release: "6.fc28", Epoch: 0, SrcName: "curl", SrcVersion: "7.59.0", SrcRelease: "6.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "rpm-libs", Version: "4.14.1", Release: "9.fc28", Epoch: 0, SrcName: "rpm", SrcVersion: "4.14.1", SrcRelease: "9.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "libsolv", Version: "0.6.35", Release: "1.fc28", Epoch: 0, SrcName: "libsolv", SrcVersion: "0.6.35", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-hawkey", Version: "0.11.1", Release: "3.fc28", Epoch: 0, SrcName: "libdnf", SrcVersion: "0.11.1", SrcRelease: "3.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "rpm-sign-libs", Version: "4.14.1", Release: "9.fc28", Epoch: 0, SrcName: "rpm", SrcVersion: "4.14.1", SrcRelease: "9.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "python3-dnf", Version: "2.7.5", Release: "12.fc28", Epoch: 0, SrcName: "dnf", SrcVersion: "2.7.5", SrcRelease: "12.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "dnf-yum", Version: "2.7.5", Release: "12.fc28", Epoch: 0, SrcName: "dnf", SrcVersion: "2.7.5", SrcRelease: "12.fc28", SrcEpoch: 0, Arch: "noarch"},
				{Name: "rpm-plugin-systemd-inhibit", Version: "4.14.1", Release: "9.fc28", Epoch: 0, SrcName: "rpm", SrcVersion: "4.14.1", SrcRelease: "9.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "nss-tools", Version: "3.38.0", Release: "1.0.fc28", Epoch: 0, SrcName: "nss", SrcVersion: "3.38.0", SrcRelease: "1.0.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "openssl-pkcs11", Version: "0.4.8", Release: "1.fc28", Epoch: 0, SrcName: "openssl-pkcs11", SrcVersion: "0.4.8", SrcRelease: "1.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "vim-minimal", Version: "8.1.328", Release: "1.fc28", Epoch: 2, SrcName: "vim", SrcVersion: "8.1.328", SrcRelease: "1.fc28", SrcEpoch: 2, Arch: "x86_64"},
				{Name: "glibc-langpack-en", Version: "2.27", Release: "32.fc28", Epoch: 0, SrcName: "glibc", SrcVersion: "2.27", SrcRelease: "32.fc28", SrcEpoch: 0, Arch: "x86_64"},
				{Name: "rootfiles", Version: "8.1", Release: "22.fc28", Epoch: 0, SrcName: "rootfiles", SrcVersion: "8.1", SrcRelease: "22.fc28", SrcEpoch: 0, Arch: "noarch"},
			},
		},
	}
	a := rpmCmdPkgAnalyzer{}
	for testname, v := range tests {
		bytes, err := ioutil.ReadFile(v.path)
		if err != nil {
			t.Errorf("%s : can't open file %s", testname, v.path)
		}
		pkgs, err := a.parsePkgInfo(bytes)
		if err != nil {
			t.Errorf("%s : catch the error : %v", testname, err)
		}
		if !reflect.DeepEqual(v.pkgs, pkgs) {
			t.Errorf("[%s]\ndiff: %s", testname, pretty.Compare(v.pkgs, pkgs))
		}
	}
}

func TestSplitFilename(t *testing.T) {
	type expected struct {
		Name    string
		Version string
		Release string
		Epoch   int
		Arch    string
	}
	var tests = map[string]struct {
		filename string
		expected expected
	}{
		"Valid": {
			filename: "foo-1.0-1.i386.rpm",
			expected: expected{
				Name:    "foo",
				Version: "1.0",
				Release: "1",
				Epoch:   0,
				Arch:    "i386",
			},
		},
		"With epoch": {
			filename: "1:bar-9-123a.ia64.rpm",
			expected: expected{
				Name:    "bar",
				Version: "9",
				Release: "123a",
				Epoch:   1,
				Arch:    "ia64",
			},
		},
	}
	for testname, v := range tests {
		name, ver, rel, epoch, arch := splitFileName(v.filename)
		if name != v.expected.Name {
			t.Errorf("[%s]Name\nexpected : %s\nactual : %s", testname, v.expected.Name, name)
		}
		if ver != v.expected.Version {
			t.Errorf("[%s]Version\nexpected : %s\nactual : %s", testname, v.expected.Version, ver)
		}
		if rel != v.expected.Release {
			t.Errorf("[%s]Release\nexpected : %s\nactual : %s", testname, v.expected.Release, rel)
		}
		if epoch != v.expected.Epoch {
			t.Errorf("[%s]Epoch\nexpected : %d\nactual : %d", testname, v.expected.Epoch, epoch)
		}
		if arch != v.expected.Arch {
			t.Errorf("[%s]Arch\nexpected : %s\nactual : %s", testname, v.expected.Arch, arch)
		}
	}
}
