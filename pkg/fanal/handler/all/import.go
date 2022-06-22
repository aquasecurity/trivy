package all

import (
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/dpkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/gomod"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)
