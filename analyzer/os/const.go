package os

import "golang.org/x/xerrors"

const (
	// RedHat is done
	RedHat = "redhat"

	// Debian is done
	Debian = "debian"

	// Ubuntu is done
	Ubuntu = "ubuntu"

	// CentOS is done
	CentOS = "centos"

	// Rocky is done
	Rocky = "rocky"

	// Alma is done
	Alma = "alma"

	// Fedora is done
	Fedora = "fedora"

	// Amazon is done
	Amazon = "amazon"

	// Oracle is done
	Oracle = "oracle"

	// FreeBSD currently doesn't support docker
	// FreeBSD = "freebsd"

	// Windows only run windows os
	// TODO : support windows
	Windows = "windows"

	// OpenSUSE is done
	OpenSUSE = "opensuse"

	// OpenSUSELeap is done
	OpenSUSELeap = "opensuse.leap"

	// OpenSUSETumbleweed is done
	OpenSUSETumbleweed = "opensuse.tumbleweed"

	// SUSE Linux Enterplise Server is done
	SLES = "suse linux enterprise server"

	// Photon OS done
	Photon = "photon"

	// Alpine is done
	Alpine = "alpine"
)

var AnalyzeOSError = xerrors.New("unable to analyze OS information")
