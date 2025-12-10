package compare

import (
	"testing"
)

func TestNormalizeConstraintString_NPM(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		want       string
	}{
		{
			name:       "single range - no normalization needed",
			constraint: ">=1.0.0, <2.0.0",
			want:       ">=1.0.0, <2.0.0",
		},
		{
			name:       "two OR ranges - space separated",
			constraint: ">=1.0.0, <2.0.0 >=2.0.0, <3.0.0",
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
		{
			name:       "three OR ranges - space separated",
			constraint: ">=1.0.0, <1.5.0 >=1.5.0, <2.0.0 >=2.0.0, <2.5.0",
			want:       ">=1.0.0, <1.5.0 || >=1.5.0, <2.0.0 || >=2.0.0, <2.5.0",
		},
		{
			name:       "already normalized with ||",
			constraint: ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
		{
			name:       "complex with pre-release versions",
			constraint: ">=14.3.0-canary.77, <15.0.5 >=15.1.0-canary.0, <15.1.9 >=15.2.0-canary.0, <15.2.6",
			want:       ">=14.3.0-canary.77, <15.0.5 || >=15.1.0-canary.0, <15.1.9 || >=15.2.0-canary.0, <15.2.6",
		},
		{
			name:       "single condition - no comma",
			constraint: ">=1.0.0",
			want:       ">=1.0.0",
		},
		{
			name:       "multiple single conditions - should normalize",
			constraint: ">=1.0.0 >=2.0.0 >=3.0.0",
			want:       ">=1.0.0 || >=2.0.0 || >=3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeConstraintString(tt.constraint, ComparerTypeNPM)
			if got != tt.want {
				t.Errorf("NormalizeConstraintString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeConstraintString_PEP440(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		want       string
	}{
		{
			name:       "single range - no normalization needed",
			constraint: ">=1.0.0, <2.0.0",
			want:       ">=1.0.0, <2.0.0",
		},
		{
			name:       "two OR ranges - space separated",
			constraint: ">=1.0.0, <2.0.0 >=2.0.0, <3.0.0",
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
		{
			name:       "three OR ranges with alpha/beta/rc",
			constraint: ">=1.0.0a0, <1.5.0b0 >=1.5.0b0, <2.0.0rc0 >=2.0.0rc0, <2.5.0",
			want:       ">=1.0.0a0, <1.5.0b0 || >=1.5.0b0, <2.0.0rc0 || >=2.0.0rc0, <2.5.0",
		},
		{
			name:       "already normalized with ||",
			constraint: ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeConstraintString(tt.constraint, ComparerTypePEP440)
			if got != tt.want {
				t.Errorf("NormalizeConstraintString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeConstraintString_RubyGems(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		want       string
	}{
		{
			name:       "single range - no normalization needed",
			constraint: ">=1.0.0, <2.0.0",
			want:       ">=1.0.0, <2.0.0",
		},
		{
			name:       "two OR ranges - space separated",
			constraint: ">=1.0.0, <2.0.0 >=2.0.0, <3.0.0",
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
		{
			name:       "three OR ranges with pre-release",
			constraint: ">=1.0.0.alpha.0, <1.5.0.beta.0 >=1.5.0.beta.0, <2.0.0.rc.0 >=2.0.0.rc.0, <2.5.0",
			want:       ">=1.0.0.alpha.0, <1.5.0.beta.0 || >=1.5.0.beta.0, <2.0.0.rc.0 || >=2.0.0.rc.0, <2.5.0",
		},
		{
			name:       "already normalized with ||",
			constraint: ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeConstraintString(tt.constraint, ComparerTypeRubyGems)
			if got != tt.want {
				t.Errorf("NormalizeConstraintString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeConstraintString_Bitnami(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		want       string
	}{
		{
			name:       "single range - no normalization needed",
			constraint: ">=1.0.0, <2.0.0",
			want:       ">=1.0.0, <2.0.0",
		},
		{
			name:       "two OR ranges - space separated",
			constraint: ">=1.0.0, <2.0.0 >=2.0.0, <3.0.0",
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
		{
			name:       "three OR ranges with revision versions",
			constraint: ">=1.0.0-0, <1.5.0-0 >=1.5.0-0, <2.0.0-0 >=2.0.0-0, <2.5.0-0",
			want:       ">=1.0.0-0, <1.5.0-0 || >=1.5.0-0, <2.0.0-0 || >=2.0.0-0, <2.5.0-0",
		},
		{
			name:       "already normalized with ||",
			constraint: ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeConstraintString(tt.constraint, ComparerTypeBitnami)
			if got != tt.want {
				t.Errorf("NormalizeConstraintString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeConstraintString_Maven(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		want       string
	}{
		{
			name:       "single range - comma AND - no normalization",
			constraint: ">= 2.0.0, <= 2.9.10.3",
			want:       ">= 2.0.0, <= 2.9.10.3",
		},
		{
			name:       "single range - space AND - no normalization",
			constraint: ">=1.7.0 <1.7.16",
			want:       ">=1.7.0 <1.7.16",
		},
		{
			name:       "two OR ranges - space AND",
			constraint: ">=1.7.0 <1.7.16 >=1.8.0 <1.8.8",
			want:       ">=1.7.0 <1.7.16 || >=1.8.0 <1.8.8",
		},
		{
			name:       "two OR ranges - comma AND",
			constraint: ">= 2.0.0, <= 2.9.10.3 >= 3.0.0, <= 3.5.0",
			want:       ">= 2.0.0, <= 2.9.10.3 || >= 3.0.0, <= 3.5.0",
		},
		{
			name:       "three OR ranges - space AND",
			constraint: ">=9.0.0.M1 <9.0.5 >=9.0.5.M1 <9.0.37 >=9.1.0.M1 <9.1.0",
			want:       ">=9.0.0.M1 <9.0.5 || >=9.0.5.M1 <9.0.37 || >=9.1.0.M1 <9.1.0",
		},
		{
			name:       "three OR ranges - comma AND",
			constraint: ">= 2.0.0, <= 2.9.10.3 >= 3.0.0, <= 3.5.0 >= 4.0.0, <= 4.2.0",
			want:       ">= 2.0.0, <= 2.9.10.3 || >= 3.0.0, <= 3.5.0 || >= 4.0.0, <= 4.2.0",
		},
		{
			name:       "already normalized with ||",
			constraint: ">=1.7.0 <1.7.16 || >=1.8.0 <1.8.8",
			want:       ">=1.7.0 <1.7.16 || >=1.8.0 <1.8.8",
		},
		{
			name:       "bracket range - single",
			constraint: "[2.9.0,2.9.10.7)",
			want:       "[2.9.0,2.9.10.7)",
		},
		{
			name:       "bracket range with OR",
			constraint: "[2.9.0,2.9.10.7) [3.0.0,3.5.0)",
			want:       "[2.9.0,2.9.10.7) || [3.0.0,3.5.0)",
		},
		{
			name:       "mixed operators - space AND",
			constraint: ">=1.0.0-alpha-1 <2.0.0 >=2.0.0-beta-1 <2.1.0 >=2.1.0-rc-1 <2.2.0",
			want:       ">=1.0.0-alpha-1 <2.0.0 || >=2.0.0-beta-1 <2.1.0 || >=2.1.0-rc-1 <2.2.0",
		},
		{
			name:       "single condition - no split",
			constraint: ">=1.0.0",
			want:       ">=1.0.0",
		},
		{
			name:       "multiple single conditions - should NOT normalize (Maven doesn't split on single >=)",
			constraint: ">=1.0.0 >=2.0.0 >=3.0.0",
			want:       ">=1.0.0 >=2.0.0 >=3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeConstraintString(tt.constraint, ComparerTypeMaven)
			if got != tt.want {
				t.Errorf("NormalizeConstraintString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeConstraintString_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		comparer   ComparerType
		want       string
	}{
		{
			name:       "empty string",
			constraint: "",
			comparer:   ComparerTypeNPM,
			want:       "",
		},
		{
			name:       "whitespace only",
			constraint: "   ",
			comparer:   ComparerTypeNPM,
			want:       "",
		},
		{
			name:       "single operator",
			constraint: ">=",
			comparer:   ComparerTypeNPM,
			want:       ">=",
		},
		{
			name:       "trailing comma - npm (edge case - not realistic but should handle)",
			constraint: ">=1.0.0, <2.0.0, >=2.0.0, <3.0.0",
			comparer:   ComparerTypeNPM,
			// This is an edge case - trailing comma means it's still part of AND group
			// So it won't split. This is actually correct behavior.
			want: ">=1.0.0, <2.0.0, >=2.0.0, <3.0.0",
		},
		{
			name:       "multiple spaces",
			constraint: ">=1.0.0,   <2.0.0    >=2.0.0,   <3.0.0",
			comparer:   ComparerTypeNPM,
			want:       ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0",
		},
		{
			name:       "maven - comma in middle of version",
			constraint: ">= 2.0.0, <= 2.9.10.3 >= 3.0.0, <= 3.5.0",
			comparer:   ComparerTypeMaven,
			want:       ">= 2.0.0, <= 2.9.10.3 || >= 3.0.0, <= 3.5.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeConstraintString(tt.constraint, tt.comparer)
			if got != tt.want {
				t.Errorf("NormalizeConstraintString() = %q, want %q", got, tt.want)
			}
		})
	}
}
