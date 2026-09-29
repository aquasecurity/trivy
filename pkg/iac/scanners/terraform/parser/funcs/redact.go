// Copied from github.com/hashicorp/terraform/internal/lang/funcs
package funcs

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"
)

func redactIfSensitive(value any, markses ...cty.ValueMarks) string {
	if Has(cty.DynamicVal.WithMarks(markses...), MarkedSensitive) {
		return "(sensitive value)"
	}
	switch v := value.(type) {
	case string:
		return fmt.Sprintf("%q", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
