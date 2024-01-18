package utils

import (
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/samber/lo"
)

// target type for which we will split pkg which is both indirect and direct
var typesForPkgSplit = []ftypes.TargetType{ftypes.NodePkg, ftypes.Yarn, ftypes.Npm, ftypes.Pnpm}

func IsPkgSplitRequired(targetType ftypes.TargetType) bool {
	return lo.Contains(typesForPkgSplit, targetType)
}
