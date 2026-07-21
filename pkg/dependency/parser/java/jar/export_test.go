package jar

// Bridge to expose jar parser internals to tests in the jar_test package.

var (
	EmbeddedPomGAV         = embeddedPomGAV
	DecodePomLicenses      = decodePomLicenses
	IsJarLicenseFile       = isJarLicenseFile
	ParsePluginLicenseName = parsePluginLicenseName
)
