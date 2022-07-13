package licensing

import "strings"

var mapping = map[string]string{
	// GPL
	"GPL2":             GPL20,
	"GPL-2":            GPL20,
	"GPL-2.0-ONLY":     GPL20,
	"GPL2+":            GPL20,
	"GPL-2+":           GPL20,
	"GPL-2.0-OR-LATER": GPL20,
	"GPL3":             GPL30,
	"GPL-3":            GPL30,
	"GPL3+":            GPL30,
	"GPL-3+":           GPL30,
	"GPL":              GPL30, // 2? 3?

	// LGPL
	"LGPL2":     LGPL20,
	"LGPL-2":    LGPL20,
	"LGPL2+":    LGPL20,
	"LGPL-2+":   LGPL20,
	"LGPL-2.1":  LGPL21,
	"LGPL-2.1+": LGPL21,

	// MPL
	"MPL1.0": MPL10,
	"MPL1":   MPL10,
	"MPL2.0": MPL20,
	"MPL2":   MPL20,

	// BSD
	"BSD":          BSD3Clause, // 2? 3?
	"BSD-2-CLAUSE": BSD2Clause,
	"BSD-3-CLAUSE": BSD3Clause,

	"APACHE": Apache20, // 1? 2?
	"ZLIB":   Zlib,
}

func Normalize(name string) string {
	if l, ok := mapping[strings.ToUpper(name)]; ok {
		return l
	}
	return name
}
