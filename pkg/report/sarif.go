package report

import (
	"io"
)

// SarifWriter implements result Writer
type SarifWriter struct {
	Output io.Writer
}

func (sw SarifWriter) Write(report Report) error {
	return nil
}
