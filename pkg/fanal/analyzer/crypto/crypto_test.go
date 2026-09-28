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
		{name: "PEM extension", filePath: "certificates/server.pem", want: true},
		{name: "DER extension", filePath: "certificates/server.der", want: true},
		{name: "CRT extension", filePath: "certificates/server.crt", want: true},
		{name: "CER extension", filePath: "certificates/server.cer", want: true},
		{name: "KEY extension", filePath: "certificates/server.key", want: true},
		{name: "mixed-case extension", filePath: "certificates/server.CrT", want: true},
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
