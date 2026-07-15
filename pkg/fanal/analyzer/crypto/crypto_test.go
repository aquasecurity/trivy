package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/crypto"
)

func TestRequired(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{name: "lowercase PEM", filePath: "certificates/server.pem", want: true},
		{name: "uppercase PEM", filePath: "certificates/server.PEM", want: true},
		{name: "mixed-case PEM", filePath: "certificates/server.PeM", want: true},
		{name: "lowercase DER", filePath: "certificates/server.der", want: true},
		{name: "uppercase DER", filePath: "certificates/server.DER", want: true},
		{name: "mixed-case DER", filePath: "certificates/server.DeR", want: true},
		{name: "lowercase CRT", filePath: "certificates/server.crt", want: true},
		{name: "uppercase CRT", filePath: "certificates/server.CRT", want: true},
		{name: "mixed-case CRT", filePath: "certificates/server.CrT", want: true},
		{name: "lowercase CER", filePath: "certificates/server.cer", want: true},
		{name: "uppercase CER", filePath: "certificates/server.CER", want: true},
		{name: "mixed-case CER", filePath: "certificates/server.CeR", want: true},
		{name: "lowercase KEY", filePath: "certificates/server.key", want: true},
		{name: "uppercase KEY", filePath: "certificates/server.KEY", want: true},
		{name: "mixed-case KEY", filePath: "certificates/server.KeY", want: true},
		{name: "public key extension", filePath: "certificates/server.pub"},
		{name: "PKCS12 extension", filePath: "certificates/server.p12"},
		{name: "extensionless", filePath: "certificates/server"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, crypto.Required(tt.filePath))
		})
	}
}
