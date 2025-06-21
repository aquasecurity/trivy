package notification

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/flag"
)

// getUsedFlags extracts the fixed flags from the provided args and returns them as a slice of strings.
func getUsedFlags(cliOptions *flag.Options) string {
	if cliOptions == nil || cliOptions.Flags == nil {
		return ""
	}

	var usedFlags []string

	for _, flagGroup := range *cliOptions.Flags {
		if flagGroup == nil {
			continue
		}

		for _, f := range flagGroup.Flags() {
			var val string
			if f.IsExplicitlySet() {
				if f.IsTelemetrySafe() {
					type flagger[T flag.FlagType] interface {
						Value() T
					}
					switch ff := f.(type) {
					case flagger[string]:
						val = ff.Value()
					case flagger[int]:
						val = strconv.Itoa(ff.Value())
					case flagger[float64]:
						val = fmt.Sprintf("%f", ff.Value())
					case flagger[bool]:
						val = strconv.FormatBool(ff.Value())
					case flagger[time.Duration]:
						val = ff.Value().String()
					case flagger[[]string]:
						val = strings.Join(ff.Value(), ",")
					default:
						val = "***" // Default case for unsupported types
					}
				} else {
					val = "***"
				}
				if f.GetName() != "" {
					usedFlags = append(usedFlags, fmt.Sprintf("--%s=%s", f.GetName(), val))
				}
			}
		}
	}
	return strings.Join(usedFlags, " ")
}
