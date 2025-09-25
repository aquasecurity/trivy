package saas

var (
	isLoggedIn  = false
	cloudConfig *CloudConfig
)

func IsLoggedIn() bool {
	return isLoggedIn
}

func setGlobalCloudConfig(config *CloudConfig) {
	if config == nil {
		return
	}

	cloudConfig = config
	cloudConfig.IsLoggedIn = true
	isLoggedIn = true
}
