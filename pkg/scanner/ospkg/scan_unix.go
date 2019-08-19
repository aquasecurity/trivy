// +build linux darwin

package ospkg

import (
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
	// TODO: Eliminate the dependency on "rpm" command
	// _ "github.com/aquasecurity/fanal/analyzer/pkg/rpm"
)
