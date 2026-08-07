package jar

// Bridge to expose jar parser internals to tests in the jar_test package.

var (
	EmbeddedPomGAV     = embeddedPomGAV
	DecodePomLicenses  = decodePomLicenses
	IsJarLicenseFile   = isJarLicenseFile
	ParseBundleLicense = parseBundleLicense
	ParseManifest      = parseManifest
)

// BundleLicense exposes the unexported bundleLicense field to tests.
func (m manifest) BundleLicense() string { return m.bundleLicense }

// PluginLicenseNames exposes the unexported pluginLicenseNames field to tests.
func (m manifest) PluginLicenseNames() []string { return m.pluginLicenseNames }
