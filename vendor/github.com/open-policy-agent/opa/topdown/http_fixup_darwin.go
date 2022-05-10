//go:build go1.18
// +build go1.18

package topdown

func fixupDarwinGo118(x, y string) string {
	switch x {
	case "x509: certificate signed by unknown authority":
		return y
	default:
		return x
	}
}
