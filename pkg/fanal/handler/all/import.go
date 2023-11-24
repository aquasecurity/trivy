package all

import (
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/syspackage"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/unpackaged"
)
