//go:build ruleguard

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// cf. https://github.com/golang/go/wiki/CodeReviewComments#declaring-empty-slices
func declareEmptySlices(m dsl.Matcher) {
	m.Match(
		`$name := []$t{}`,
		`$name := make([]$t, 0)`,
	).
		Suggest(`var $name []$t`).
		Report(`replace '$$' with 'var $name []$t'`)
}

// cf. https://github.com/uber-go/guide/blob/master/style.md#initializing-maps
func initializeMaps(m dsl.Matcher) {
	m.Match(`map[$key]$value{}`).
		Suggest(`make(map[$key]$value)`).
		Report(`replace '$$' with 'make(map[$key]$value)`)
}

// While errors.Join from standard library can combine multiple errors,
// we use hashicorp/go-multierror for more user-friendly error outputs.
func errorsJoin(m dsl.Matcher) {
	m.Match(`errors.Join($x...)`).
		Report("use github.com/hashicorp/go-multierror.Append instead of errors.Join.")

	m.Match(`errors.Join($*args)`).
		Report("use github.com/hashicorp/go-multierror.Append instead of errors.Join.")
}

func mapSet(m dsl.Matcher) {
	m.Match(`map[$x]struct{}`).
		Report("use github.com/aquasecurity/trivy/pkg/set.Set instead of map.")
}

// Enforce usage of x/os package for temporary file operations
func tempFileOps(m dsl.Matcher) {
	m.Match(`os.CreateTemp($*args)`).
		Where(!m.File().Name.Matches(`.*_test\.go$`)).
		Suggest(`xos.CreateTemp($args)`).
		Report("use github.com/aquasecurity/trivy/pkg/x/os.CreateTemp instead of os.CreateTemp for process-safe temp file cleanup")

	m.Match(`os.MkdirTemp($*args)`).
		Where(!m.File().Name.Matches(`.*_test\.go$`)).
		Suggest(`xos.MkdirTemp($args)`).
		Report("use github.com/aquasecurity/trivy/pkg/x/os.MkdirTemp instead of os.MkdirTemp for process-safe temp file cleanup")
}
