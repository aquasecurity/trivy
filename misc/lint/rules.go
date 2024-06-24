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
