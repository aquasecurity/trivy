package testutil

import (
	"github.com/samber/lo"
	"runtime"
)

var ErrNotExist string = lo.Ternary(runtime.GOOS == "windows",
	"The system cannot find the file specified.",
	"no such file or directory")
