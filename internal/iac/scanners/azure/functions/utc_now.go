package functions

import (
	"strings"
	"time"
)

func UTCNow(args ...any) any {
	if len(args) > 1 {
		return nil
	}

	if len(args) == 1 {
		format, ok := args[0].(string)
		if ok {
			goFormat := convertFormat(format)
			return time.Now().UTC().Format(goFormat)
		}
	}

	return time.Now().UTC().Format(time.RFC3339)
}

// don't look directly at this code
func convertFormat(format string) string {
	goFormat := format
	goFormat = strings.ReplaceAll(goFormat, "yyyy", "2006")
	goFormat = strings.ReplaceAll(goFormat, "yy", "06")
	goFormat = strings.ReplaceAll(goFormat, "MMMM", "January")
	goFormat = strings.ReplaceAll(goFormat, "MMM", "Jan")
	goFormat = strings.ReplaceAll(goFormat, "MM", "01")
	goFormat = strings.ReplaceAll(goFormat, "M", "1")
	goFormat = strings.ReplaceAll(goFormat, "dd", "02")
	goFormat = strings.ReplaceAll(goFormat, "d", "2")
	goFormat = strings.ReplaceAll(goFormat, "HH", "15")
	goFormat = strings.ReplaceAll(goFormat, "H", "3")
	goFormat = strings.ReplaceAll(goFormat, "hh", "03")
	goFormat = strings.ReplaceAll(goFormat, "h", "3")
	goFormat = strings.ReplaceAll(goFormat, "mm", "04")
	goFormat = strings.ReplaceAll(goFormat, "m", "4")
	goFormat = strings.ReplaceAll(goFormat, "ss", "05")
	goFormat = strings.ReplaceAll(goFormat, "s", "5")
	goFormat = strings.ReplaceAll(goFormat, "tt", "PM")
	goFormat = strings.ReplaceAll(goFormat, "t", "PM")
	return goFormat

}
