package all

import (
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/dpkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/gomod"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/unpackaged"
	// _ "github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
)
