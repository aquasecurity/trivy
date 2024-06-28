package iam

func IsWildcardAllowed(actions ...string) (bool, string) {
	for _, action := range actions {
		if _, exist := AllowedActionsForResourceWildcardsMap[action]; !exist {
			return false, action
		}
	}
	return true, ""
}
