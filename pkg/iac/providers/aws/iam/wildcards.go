package iam

func IsWildcardAllowed(actions ...string) (bool, string) {
	for _, action := range actions {
		if _, exist := allowedActionsForResourceWildcardsMap[action]; !exist {
			return false, action
		}
	}
	return true, ""
}
