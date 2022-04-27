package cloudfront

import "github.com/aquasecurity/defsec/parsers/types"

type Cloudfront struct {
	types.Metadata
	Distributions []Distribution
}

type Distribution struct {
	types.Metadata
	WAFID                  types.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
}

type Logging struct {
	types.Metadata
	Bucket types.StringValue
}

type CacheBehaviour struct {
	types.Metadata
	ViewerProtocolPolicy types.StringValue
}

const (
	ViewerPolicyProtocolAllowAll        = "allow-all"
	ViewerPolicyProtocolHTTPSOnly       = "https-only"
	ViewerPolicyProtocolRedirectToHTTPS = "redirect-to-https"
)

const (
	ProtocolVersionTLS1_2 = "TLSv1.2_2021"
)

type ViewerCertificate struct {
	types.Metadata
	MinimumProtocolVersion types.StringValue
}
