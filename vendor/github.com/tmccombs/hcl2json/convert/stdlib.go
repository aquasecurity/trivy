package convert

import (
	hcl "github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// a subset of functions used in terraform
// that can be used when simplifying during conversion
var evalContext = hcl.EvalContext {
	Functions: map[string]function.Function{
		// numeric
		"abs":      stdlib.AbsoluteFunc,
		"ceil":     stdlib.CeilFunc,
		"floor":    stdlib.FloorFunc,
		"log":      stdlib.LogFunc,
		"max":      stdlib.MaxFunc,
		"min":      stdlib.MinFunc,
		"parseint": stdlib.ParseIntFunc,
		"pow":      stdlib.PowFunc,
		"signum":   stdlib.SignumFunc,

		// string
		"chomp": stdlib.ChompFunc,
		"format": stdlib.FormatFunc,
		"formatlist": stdlib.FormatListFunc,
		"indent": stdlib.IndentFunc,
		"join": stdlib.JoinFunc,
		"split": stdlib.SplitFunc,
		"strrev": stdlib.ReverseFunc,
		"trim": stdlib.TrimFunc,
		"trimprefix": stdlib.TrimPrefixFunc,
		"trimsuffix": stdlib.TrimSuffixFunc,
		"trimspace": stdlib.TrimSpaceFunc,

		// collections
		"chunklist": stdlib.ChunklistFunc,
		"concat": stdlib.ConcatFunc,
		"distinct": stdlib.DistinctFunc,
		"flatten": stdlib.FlattenFunc,
		"length": stdlib.LengthFunc,
		"merge": stdlib.MergeFunc,
		"reverse": stdlib.ReverseListFunc,
		"sort": stdlib.SortFunc,

		// encoding
		"csvdecode": stdlib.CSVDecodeFunc,
		"jsondecode": stdlib.JSONDecodeFunc,
		"jsonencode": stdlib.JSONEncodeFunc,


		// time
		"formatdate": stdlib.FormatDateFunc,
		"timeadd": stdlib.TimeAddFunc,

	},
}
