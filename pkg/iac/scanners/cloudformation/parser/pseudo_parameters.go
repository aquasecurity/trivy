package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

type pseudoParameter struct {
	t   cftypes.CfType
	val interface{}
	raw interface{}
}

var pseudoParameters = map[string]pseudoParameter{
	"AWS::AccountId": {t: cftypes.String, val: "123456789012"},
	"AWS::NotificationARNs": {
		t: cftypes.List,
		val: []*Property{
			{
				Inner: PropertyInner{
					Type:  cftypes.String,
					Value: "notification::arn::1",
				},
			},
			{
				Inner: PropertyInner{
					Type:  cftypes.String,
					Value: "notification::arn::2",
				},
			},
		},
		raw: []string{"notification::arn::1", "notification::arn::2"},
	},
	"AWS::NoValue":   {t: cftypes.String, val: ""},
	"AWS::Partition": {t: cftypes.String, val: "aws"},
	"AWS::Region":    {t: cftypes.String, val: "eu-west-1"},
	"AWS::StackId":   {t: cftypes.String, val: "arn:aws:cloudformation:eu-west-1:stack/ID"},
	"AWS::StackName": {t: cftypes.String, val: "cfsec-test-stack"},
	"AWS::URLSuffix": {t: cftypes.String, val: "amazonaws.com"},
}

func (p pseudoParameter) getRawValue() interface{} {
	switch p.t {
	case cftypes.List:
		return p.raw
	default:
		return p.val
	}
}
