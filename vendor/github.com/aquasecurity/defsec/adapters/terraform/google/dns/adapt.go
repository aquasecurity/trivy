package dns

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/dns"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		ManagedZones: adaptManagedZones(modules),
	}
}

func adaptManagedZones(modules terraform.Modules) []dns.ManagedZone {
	var managedZones []dns.ManagedZone
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_dns_managed_zone") {
			managedZone := adaptManagedZone(resource)
			for _, data := range module.GetDatasByType("google_dns_keys") {
				managedZone.DNSSec.DefaultKeySpecs = adaptKeySpecs(data)
			}
			managedZones = append(managedZones, managedZone)
		}
	}
	return managedZones
}

func adaptManagedZone(resource *terraform.Block) dns.ManagedZone {

	zone := dns.ManagedZone{
		Metadata: resource.GetMetadata(),
		DNSSec: dns.DNSSec{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			DefaultKeySpecs: dns.KeySpecs{
				Metadata: resource.GetMetadata(),
				KeySigningKey: dns.Key{
					Metadata:  resource.GetMetadata(),
					Algorithm: types.StringDefault("", resource.GetMetadata()),
				},
				ZoneSigningKey: dns.Key{
					Metadata:  resource.GetMetadata(),
					Algorithm: types.StringDefault("", resource.GetMetadata()),
				},
			},
		},
	}

	if resource.HasChild("dnssec_config") {
		DNSSecBlock := resource.GetBlock("dnssec_config")

		stateAttr := DNSSecBlock.GetAttribute("state")
		if stateAttr.Equals("on") {
			zone.DNSSec.Enabled = types.Bool(true, DNSSecBlock.GetMetadata())
		} else if stateAttr.Equals("off") || stateAttr.Equals("transfer") {
			zone.DNSSec.Enabled = types.Bool(false, DNSSecBlock.GetMetadata())
		}

		if DNSSecBlock.HasChild("default_key_specs") {
			DefaultKeySpecsBlock := DNSSecBlock.GetBlock("default_key_specs")

			algorithmAttr := DefaultKeySpecsBlock.GetAttribute("algorithm")
			algorithmVal := algorithmAttr.AsStringValueOrDefault("", DefaultKeySpecsBlock)

			keyTypeAttr := DefaultKeySpecsBlock.GetAttribute("key_type")
			if keyTypeAttr.Equals("keySigning") {
				zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm = algorithmVal
			} else if keyTypeAttr.Equals("zoneSigning") {
				zone.DNSSec.DefaultKeySpecs.ZoneSigningKey.Algorithm = algorithmVal
			}
		}
	}
	return zone
}

func adaptKeySpecs(resource *terraform.Block) dns.KeySpecs {
	keySpecs := dns.KeySpecs{
		Metadata: resource.GetMetadata(),
		KeySigningKey: dns.Key{
			Metadata:  resource.GetMetadata(),
			Algorithm: types.String("", resource.GetMetadata()),
		},
		ZoneSigningKey: dns.Key{
			Metadata:  resource.GetMetadata(),
			Algorithm: types.String("", resource.GetMetadata()),
		},
	}
	KeySigningKeysBlock := resource.GetBlock("key_signing_keys")
	if KeySigningKeysBlock.IsNotNil() {
		algorithmAttr := KeySigningKeysBlock.GetAttribute("algorithm")
		keySpecs.KeySigningKey.Algorithm = algorithmAttr.AsStringValueOrDefault("", KeySigningKeysBlock)
	}

	ZoneSigningKeysBlock := resource.GetBlock("zone_signing_keys")
	if ZoneSigningKeysBlock.IsNotNil() {
		algorithmAttr := ZoneSigningKeysBlock.GetAttribute("algorithm")
		keySpecs.ZoneSigningKey.Algorithm = algorithmAttr.AsStringValueOrDefault("", ZoneSigningKeysBlock)
	}

	return keySpecs
}
