package licensing

import (
	"regexp"
	"strings"
)

var mapping = map[string]string{
	// GPL
	"GPL-1":                          GPL10,
	"GPL-1+":                         GPL10,
	"GPL 1.0":                        GPL10,
	"GPL 1":                          GPL10,
	"GPL2":                           GPL20,
	"GPL 2.0":                        GPL20,
	"GPL 2":                          GPL20,
	"GPL-2":                          GPL20,
	"GPL-2.0-ONLY":                   GPL20,
	"GPL2+":                          GPL20,
	"GPLV2":                          GPL20,
	"GPLV2+":                         GPL20,
	"GPL-2+":                         GPL20,
	"GPL-2.0+":                       GPL20,
	"GPL-2.0-OR-LATER":               GPL20,
	"GPL-2+ WITH AUTOCONF EXCEPTION": GPL20withautoconfexception,
	"GPL-2+-with-bison-exception":    GPL20withbisonexception,
	"GPL3":                           GPL30,
	"GPL 3.0":                        GPL30,
	"GPL 3":                          GPL30,
	"GPLV3":                          GPL30,
	"GPLV3+":                         GPL30,
	"GPL-3":                          GPL30,
	"GPL-3.0-ONLY":                   GPL30,
	"GPL3+":                          GPL30,
	"GPL-3+":                         GPL30,
	"GPL-3.0-OR-LATER":               GPL30,
	"GPL-3+ WITH AUTOCONF EXCEPTION": GPL30withautoconfexception,
	"GPL-3+-WITH-BISON-EXCEPTION":    GPL20withbisonexception,
	"GPL":                            GPL30, // 2? 3?

	// LGPL
	"LGPL2":      LGPL20,
	"LGPL 2":     LGPL20,
	"LGPL 2.0":   LGPL20,
	"LGPL-2":     LGPL20,
	"LGPL2+":     LGPL20,
	"LGPL-2+":    LGPL20,
	"LGPL-2.0+":  LGPL20,
	"LGPL-2.1":   LGPL21,
	"LGPL 2.1":   LGPL21,
	"LGPL-2.1+":  LGPL21,
	"LGPLV2.1+":  LGPL21,
	"LGPL-3":     LGPL30,
	"LGPL 3":     LGPL30,
	"LGPL-3+":    LGPL30,
	"LGPL":       LGPL30, // 2? 3?
	"GNU LESSER": LGPL30, // 2? 3?

	// MPL
	"MPL1.0":  MPL10,
	"MPL1":    MPL10,
	"MPL 1.0": MPL10,
	"MPL 1":   MPL10,
	"MPL2.0":  MPL20,
	"MPL 2.0": MPL20,
	"MPL2":    MPL20,
	"MPL 2":   MPL20,

	// BSD
	"BSD":          BSD3Clause, // 2? 3?
	"BSD-2-CLAUSE": BSD2Clause,
	"BSD-3-CLAUSE": BSD3Clause,
	"BSD-4-CLAUSE": BSD4Clause,

	"APACHE":     Apache20, // 1? 2?
	"APACHE 2.0": Apache20,
	"RUBY":       Ruby,
	"ZLIB":       Zlib,

	// Public Domain
	"PUBLIC DOMAIN": Unlicense,
}

// Split licenses without considering "and"/"or"
// examples:
// 'GPL-1+,GPL-2' => {"GPL-1+", "GPL-2"}
// 'GPL-1+ or Artistic or Artistic-dist' => {"GPL-1+", "Artistic", "Artistic-dist"}
// 'LGPLv3+_or_GPLv2+' => {"LGPLv3+", "GPLv2"}
// 'BSD-3-CLAUSE and GPL-2' => {"BSD-3-CLAUSE", "GPL-2"}
// 'GPL-1+ or Artistic, and BSD-4-clause-POWERDOG' => {"GPL-1+", "Artistic", "BSD-4-clause-POWERDOG"}
// 'BSD 3-Clause License or Apache License, Version 2.0' => {"BSD 3-Clause License", "Apache License, Version 2.0"}
// var LicenseSplitRegexp = regexp.MustCompile("(,?[_ ]+or[_ ]+)|(,?[_ ]+and[_ ])|(,[ ]*)")

var licenseSplitRegexp = regexp.MustCompile("(,?[_ ]+(?:or|and)[_ ]+)|(,[ ]*)")

func Normalize(name string) string {
	if l, ok := mapping[strings.ToUpper(name)]; ok {
		return l
	}
	return name
}

func SplitLicenses(str string) []string {
	var licenses []string
	for _, maybeLic := range licenseSplitRegexp.Split(str, -1) {
		lower := strings.ToLower(maybeLic)
		if (strings.HasPrefix(lower, "ver ") || strings.HasPrefix(lower, "version ")) && len(licenses) > 0 {
			licenses[len(licenses)-1] += ", " + maybeLic
		} else {
			licenses = append(licenses, maybeLic)
		}
	}
	return licenses
}
