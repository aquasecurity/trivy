// +build linux darwin

package ospkg

import (
	_ "github.com/knqyf263/fanal/analyzer/pkg/rpmcmd"
	// TODO: Eliminate the dependency on "rpm" command
	// _ "github.com/knqyf263/fanal/analyzer/pkg/rpm"
)
