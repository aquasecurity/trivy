package parser

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/assert"
)

func newProp(inner PropertyInner) *Property {
	return &Property{
		name:  "test_prop",
		ctx:   &FileContext{},
		rng:   types.NewRange("testfile", 1, 1, "", nil),
		Inner: inner,
	}
}

func Test_EqualTo(t *testing.T) {
	tests := []struct {
		name       string
		property   *Property
		checkValue interface{}
		opts       []EqualityOptions
		isEqual    bool
	}{
		{
			name:       "prop is nil",
			property:   nil,
			checkValue: "some value",
			isEqual:    false,
		},
		{
			name: "compare strings",
			property: newProp(PropertyInner{
				Type:  cftypes.String,
				Value: "is str",
			}),
			checkValue: "is str",
			isEqual:    true,
		},
		{
			name: "compare strings ignoring case",
			property: newProp(PropertyInner{
				Type:  cftypes.String,
				Value: "is str",
			}),
			opts:       []EqualityOptions{IgnoreCase},
			checkValue: "Is StR",
			isEqual:    true,
		},
		{
			name: "strings ate not equal",
			property: newProp(PropertyInner{
				Type:  cftypes.String,
				Value: "some value",
			}),
			checkValue: "some other value",
			isEqual:    false,
		},
		{
			name: "compare prop with a int represented by a string",
			property: newProp(PropertyInner{
				Type:  cftypes.Int,
				Value: 147,
			}),
			checkValue: "147",
			isEqual:    true,
		},
		{
			name: "compare ints",
			property: newProp(PropertyInner{
				Type:  cftypes.Int,
				Value: 701,
			}),
			checkValue: 701,
			isEqual:    true,
		},
		{
			name: "compare bools",
			property: newProp(PropertyInner{
				Type:  cftypes.Bool,
				Value: true,
			}),
			checkValue: true,
			isEqual:    true,
		},
		{
			name: "prop is string fn",
			property: newProp(PropertyInner{
				Type: cftypes.Map,
				Value: map[string]*Property{
					"Fn::If": {
						Inner: PropertyInner{
							Type: cftypes.List,
							Value: []*Property{
								{
									Inner: PropertyInner{
										Type:  cftypes.Bool,
										Value: false,
									},
								},
								{
									Inner: PropertyInner{
										Type:  cftypes.String,
										Value: "bad",
									},
								},
								{
									Inner: PropertyInner{
										Type:  cftypes.String,
										Value: "some value",
									},
								},
							},
						},
					},
				},
			}),
			checkValue: "some value",
			isEqual:    true,
		},
		{
			name: "prop is int fn",
			property: newProp(PropertyInner{
				Type: cftypes.Map,
				Value: map[string]*Property{
					"Fn::If": {
						Inner: PropertyInner{
							Type: cftypes.List,
							Value: []*Property{
								{
									Inner: PropertyInner{
										Type:  cftypes.Bool,
										Value: true,
									},
								},
								{
									Inner: PropertyInner{
										Type:  cftypes.Int,
										Value: 121,
									},
								},
								{
									Inner: PropertyInner{
										Type:  cftypes.Int,
										Value: -1,
									},
								},
							},
						},
					},
				},
			}),
			checkValue: 121,
			isEqual:    true,
		},
		{
			name: "prop is bool fn",
			property: newProp(PropertyInner{
				Type: cftypes.Map,
				Value: map[string]*Property{
					"Fn::Equals": {
						Inner: PropertyInner{
							Type: cftypes.List,
							Value: []*Property{
								{
									Inner: PropertyInner{
										Type:  cftypes.String,
										Value: "foo",
									},
								},
								{
									Inner: PropertyInner{
										Type:  cftypes.String,
										Value: "foo",
									},
								},
							},
						},
					},
				},
			}),
			checkValue: true,
			isEqual:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isEqual, tt.property.EqualTo(tt.checkValue, tt.opts...))
		})
	}
}
