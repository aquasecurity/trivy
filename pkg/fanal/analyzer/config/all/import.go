package all

import (
	_ "github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/dockerfile"
	_ "github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/helm"
	_ "github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/json"
	_ "github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/terraform"
	_ "github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/yaml"
)
