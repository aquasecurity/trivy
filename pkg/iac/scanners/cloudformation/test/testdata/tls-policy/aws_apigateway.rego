# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.aws.apigateway

import rego.v1

import data.lib.cloud.value

# Patterns rather than exact names, so policies added to the same families
# are covered without a change here.
secure_security_policies := [
	"TLS_1_2",
	"SecurityPolicy_TLS12_*_EDGE",
	"SecurityPolicy_TLS13_*",
]

# True if the security policy permits TLS versions below 1.2.
# Unresolvable values yield no result.
is_outdated_security_policy(policy) if {
	value.is_known(policy)
	not _is_secure_security_policy(policy)
}

_is_secure_security_policy(policy) if {
	some pattern in secure_security_policies
	glob.match(pattern, [], policy.value)
}
