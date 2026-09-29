package testutil

import (
	"runtime"

	"github.com/samber/lo"
)

var ErrNotExist string = lo.Ternary(runtime.GOOS == "windows",
	"The system cannot find the file specified.",
	"no such file or directory")
