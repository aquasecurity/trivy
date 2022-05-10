package elb

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/elb"
)

func getLoadBalancers(ctx parser.FileContext) (loadbalancers []elb.LoadBalancer) {

	loadBalanacerResources := ctx.GetResourceByType("AWS::ElasticLoadBalancingV2::LoadBalancer")

	for _, r := range loadBalanacerResources {
		lb := elb.LoadBalancer{
			Metadata:                r.Metadata(),
			Type:                    r.GetStringProperty("Type", "application"),
			DropInvalidHeaderFields: checkForDropInvalidHeaders(r),
			Internal:                isInternal(r),
			Listeners:               getListeners(r, ctx),
		}
		loadbalancers = append(loadbalancers, lb)
	}

	return loadbalancers
}

func getListeners(lbr *parser.Resource, ctx parser.FileContext) (listeners []elb.Listener) {

	listenerResources := ctx.GetResourceByType("AWS::ElasticLoadBalancingV2::Listener")

	for _, r := range listenerResources {
		if r.GetStringProperty("LoadBalancerArn").Value() == lbr.ID() {
			listener := elb.Listener{
				Metadata:      r.Metadata(),
				Protocol:      r.GetStringProperty("Protocol", "HTTP"),
				TLSPolicy:     r.GetStringProperty("SslPolicy", "ELBSecurityPolicy-2016-08"),
				DefaultAction: getDefaultListenerAction(r),
			}

			listeners = append(listeners, listener)
		}
	}
	return listeners
}

func getDefaultListenerAction(r *parser.Resource) (action elb.Action) {
	defaultActionsProp := r.GetProperty("DefaultActions")
	if defaultActionsProp.IsNotList() || len(defaultActionsProp.AsList()) == 0 {
		return action
	}
	action.Type = defaultActionsProp.AsList()[0].GetProperty("Type").AsStringValue()
	return action
}

func isInternal(r *parser.Resource) types.BoolValue {
	schemeProp := r.GetProperty("Scheme")
	if schemeProp.IsNotString() {
		return r.BoolDefault(false)
	}
	return types.Bool(schemeProp.EqualTo("internal", parser.IgnoreCase), schemeProp.Metadata())
}

func checkForDropInvalidHeaders(r *parser.Resource) types.BoolValue {
	attributesProp := r.GetProperty("LoadBalancerAttributes")
	if attributesProp.IsNotList() {
		return types.BoolDefault(false, r.Metadata())
	}

	for _, attr := range attributesProp.AsList() {
		if attr.IsNotMap() {
			continue
		}

		if attr.AsMap()["Key"].AsString() == "routing.http.drop_invalid_header_fields.enabled" {
			val := attr.AsMap()["Value"]
			if val.IsBool() {
				return val.AsBoolValue()
			}

		}
	}

	return r.BoolDefault(false)
}
