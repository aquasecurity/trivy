package expression_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/licensing/expression"
)

func TestSPDXLicenseIDByURL(t *testing.T) {
	// Inputs are already-normalized URLs (see licensing.NormalizeLicenseURL),
	// as the caller is responsible for normalization.
	tests := []struct {
		name   string
		url    string
		want   string
		wantOK bool
	}{
		{
			name:   "apache-2.0 upstream URL",
			url:    "apache.org/licenses/license-2.0",
			want:   "Apache-2.0",
			wantOK: true,
		},
		{
			name:   "opensource.org mit",
			url:    "opensource.org/license/mit",
			want:   "MIT",
			wantOK: true,
		},
		{
			name:   "license family collapsed to its base license at generation time",
			url:    "opensource.org/license/gpl-2.0",
			want:   "GPL-2.0",
			wantOK: true,
		},
		{
			name:   "ambiguous URL of genuinely different licenses is dropped at generation time",
			url:    "microsoft.com/opensource/licenses.mspx",
			wantOK: false,
		},
		{
			name:   "ambiguous URL shared by multiple IDs is dropped at generation time",
			url:    "mozilla.org/mpl/2.0",
			wantOK: false,
		},
		{
			name:   "unknown URL",
			url:    "example.com/my-license",
			wantOK: false,
		},
		{
			name:   "empty",
			url:    "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := expression.SPDXLicenseIDByURL(tt.url)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
