package all

import (
	_ "github.com/deepfactor-io/trivy/pkg/fanal/handler/gomod"
	_ "github.com/deepfactor-io/trivy/pkg/fanal/handler/misconf"
	_ "github.com/deepfactor-io/trivy/pkg/fanal/handler/sysfile"
	_ "github.com/deepfactor-io/trivy/pkg/fanal/handler/unpackaged"
)
