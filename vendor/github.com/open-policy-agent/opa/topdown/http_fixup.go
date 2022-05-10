//go:build !go1.18 || !darwin
// +build !go1.18 !darwin

package topdown

func fixupDarwinGo118(x string, _ string) string {
	return x
}
