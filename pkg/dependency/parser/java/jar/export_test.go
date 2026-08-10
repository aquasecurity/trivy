package jar

import "io"

// Bridge to expose jar parser internals to tests in the jar_test package.

var (
	EmbeddedPomGAV         = embeddedPomGAV
	DecodePomLicenses      = decodePomLicenses
	IsJarLicenseFile       = isJarLicenseFile
	ParsePluginLicenseName = parsePluginLicenseName
)

// ManifestProperties parses a MANIFEST.MF and returns the artifact properties its main section yields.
func ManifestProperties(r io.Reader, filePath string) (Properties, error) {
	m, err := parseManifestMainSection(r)
	if err != nil {
		return Properties{}, err
	}
	return m.properties(filePath), nil
}
