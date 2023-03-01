package all

import (
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/unpackaged"
)
