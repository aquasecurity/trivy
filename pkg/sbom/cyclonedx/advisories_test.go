package cyclonedx

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	syntheticApacheEncoded = "https://lists.apache.org/thread.html/example%40%3Cdev.apache.org%3E"
	syntheticApachePartial = "https://lists.apache.org/thread.html/example@%3Cdev.apache.org%3E"
	syntheticApacheLiteral = "https://lists.apache.org/thread.html/example@<dev.apache.org>"
	syntheticApacheCanon   = "https://lists.apache.org/thread.html/example@%3Cdev.apache.org%3E"
)

func TestAdvisories_equivalentPathEncodingVariants(t *testing.T) {
	m := Marshaler{}
	advs := m.advisories([]string{
		syntheticApacheEncoded,
		syntheticApachePartial,
		syntheticApacheLiteral,
	})
	require.NotNil(t, advs)
	require.Len(t, *advs, 1)
	assert.Equal(t, syntheticApacheCanon, (*advs)[0].URL)
}

func TestAdvisories_primaryURLAndReferencesDedup(t *testing.T) {
	m := Marshaler{}
	advs := m.advisories([]string{
		syntheticApacheEncoded,
		syntheticApacheLiteral,
	})
	require.NotNil(t, advs)
	require.Len(t, *advs, 1)
	assert.Equal(t, syntheticApacheCanon, (*advs)[0].URL)
}

func TestAdvisories_noRawAngleBracketsInURLs(t *testing.T) {
	m := Marshaler{}
	advs := m.advisories([]string{
		syntheticApacheEncoded,
		syntheticApachePartial,
		syntheticApacheLiteral,
	})
	require.NotNil(t, advs)
	for _, adv := range *advs {
		assert.NotContains(t, adv.URL, "<")
		assert.NotContains(t, adv.URL, ">")
	}
}

func TestAdvisories_distinctURLsRemainDistinct(t *testing.T) {
	m := Marshaler{}
	advs := m.advisories([]string{
		"https://example.com/advisory/one",
		"https://example.com/advisory/two",
	})
	require.NotNil(t, advs)
	require.Len(t, *advs, 2)
	urls := advisoryURLs(advs)
	assert.Contains(t, urls, "https://example.com/advisory/one")
	assert.Contains(t, urls, "https://example.com/advisory/two")
}

func TestAdvisories_trimNonURLInfoPreservesFirstURLToken(t *testing.T) {
	m := Marshaler{}
	advs := m.advisories([]string{
		"https://example.com/advisory/one additional text",
	})
	require.NotNil(t, advs)
	require.Len(t, *advs, 1)
	assert.Equal(t, "https://example.com/advisory/one", (*advs)[0].URL)
}

func TestCanonicalizeAdvisoryURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantOK  bool
	}{
		{
			name:   "encoded path",
			raw:    syntheticApacheEncoded,
			want:   syntheticApacheCanon,
			wantOK: true,
		},
		{
			name:   "literal angle brackets",
			raw:    syntheticApacheLiteral,
			want:   syntheticApacheCanon,
			wantOK: true,
		},
		{
			name:   "invalid url",
			raw:    "not-a-url",
			want:   "",
			wantOK: false,
		},
		{
			name:   "missing host",
			raw:    "https:///path",
			want:   "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := canonicalizeAdvisoryURL(tt.raw)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func advisoryURLs(advs *[]cdx.Advisory) []string {
	if advs == nil {
		return nil
	}
	urls := make([]string, 0, len(*advs))
	for _, adv := range *advs {
		urls = append(urls, adv.URL)
	}
	return urls
}
