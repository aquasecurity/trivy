# METADATA
# title: Elasticsearch domain endpoint is using outdated TLS policy.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html
# custom:
#   id: AWS-0126
#   long_id: aws-elasticsearch-use-secure-tls-policy
#   aliases:
#     - AVD-AWS-0126
#     - use-secure-tls-policy
#     - aws-elasticsearch-use-secure-tls-policy
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   recommended_action: Use the most modern TLS/SSL policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticsearch
#             provider: aws
#   examples: checks/cloud/aws/elasticsearch/use_secure_tls_policy.yaml
package builtin.aws.elasticsearch.aws0126

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	value.is_known(domain.endpoint.tlspolicy)
	not is_tls_policy_secure(domain)
	res := result.new(
		"Domain does not have a secure TLS policy.",
		metadata.obj_by_path(domain, ["endpoint", "tlspolicy"]),
	)
}

# Patterns rather than exact names, so policies added to the same families
# are covered without a change here.
secure_tls_policies := ["Policy-Min-TLS-1-2-*", "Policy-Min-TLS-1-3-*"]

is_tls_policy_secure(domain) if {
	some pattern in secure_tls_policies
	glob.match(pattern, [], domain.endpoint.tlspolicy.value)
}
