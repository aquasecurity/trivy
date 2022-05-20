//go:build offline
// +build offline

package option

func init() {
	disableNetworking = "true"
}
