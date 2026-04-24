package clientip

import (
	"errors"
	"net/netip"
	"testing"
)

func TestValidateProxyCount(t *testing.T) {
	tests := []struct {
		name         string
		minProxies   int
		maxProxies   int
		trustedCIDRs []netip.Prefix
		trustedCount int
		wantErr      error
	}{
		{name: "within range", minProxies: 1, maxProxies: 3, trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, trustedCount: 2},
		{name: "at minimum", minProxies: 1, maxProxies: 3, trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, trustedCount: 1},
		{name: "at maximum", minProxies: 1, maxProxies: 3, trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, trustedCount: 3},
		{name: "no trusted proxies allowed when minimum is zero", minProxies: 0, maxProxies: 3, trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, trustedCount: 0},
		{name: "no trusted proxies with minimum requirement", minProxies: 1, maxProxies: 3, trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, trustedCount: 0, wantErr: ErrNoTrustedProxies},
		{name: "below minimum", minProxies: 2, maxProxies: 3, trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, trustedCount: 1, wantErr: ErrTooFewTrustedProxies},
		{name: "above maximum", minProxies: 1, maxProxies: 2, trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, trustedCount: 3, wantErr: ErrTooManyTrustedProxies},
		{name: "no minimum requirement", minProxies: 0, maxProxies: 3, trustedCIDRs: []netip.Prefix{}, trustedCount: 0},
		{name: "no maximum limit", minProxies: 1, maxProxies: 0, trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, trustedCount: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProxyCountPolicy(tt.trustedCount, proxyPolicy{
				TrustedProxyCIDRs: tt.trustedCIDRs,
				MinTrustedProxies: tt.minProxies,
				MaxTrustedProxies: tt.maxProxies,
			})
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("validateProxyCountPolicy() error = %v, want nil", err)
				}
				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateProxyCountPolicy() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAnalyzeChainRightmostNoCIDRs(t *testing.T) {
	tests := []struct {
		name              string
		parts             []string
		maxTrustedProxies int
		wantClientIndex   int
		wantTrustedCount  int
	}{
		{name: "no max proxies", parts: []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"}, maxTrustedProxies: 0, wantClientIndex: 0, wantTrustedCount: 3},
		{name: "max 1 proxy", parts: []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"}, maxTrustedProxies: 1, wantClientIndex: 1, wantTrustedCount: 1},
		{name: "max 2 proxies", parts: []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"}, maxTrustedProxies: 2, wantClientIndex: 0, wantTrustedCount: 2},
		{name: "single IP", parts: []string{"1.1.1.1"}, maxTrustedProxies: 1, wantClientIndex: 0, wantTrustedCount: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, _, err := analyzeChainRightmost(tt.parts, proxyPolicy{MaxTrustedProxies: tt.maxTrustedProxies}, true, parseIP)
			if err != nil {
				t.Fatalf("analyzeChainRightmost() error = %v", err)
			}

			if analysis.ClientIndex != tt.wantClientIndex {
				t.Errorf("clientIndex = %d, want %d", analysis.ClientIndex, tt.wantClientIndex)
			}
			if analysis.TrustedCount != tt.wantTrustedCount {
				t.Errorf("trustedCount = %d, want %d", analysis.TrustedCount, tt.wantTrustedCount)
			}
		})
	}
}

func TestAnalyzeChainRightmostWithCIDRs(t *testing.T) {
	policy := proxyPolicy{TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	policy.TrustedProxyMatch = newPrefixMatcher(policy.TrustedProxyCIDRs)

	tests := []struct {
		name               string
		parts              []string
		minProxies         int
		maxProxies         int
		wantClientIndex    int
		wantTrustedCount   int
		wantErr            error
		wantTrustedIndices []int
	}{
		{name: "one trusted proxy at end", parts: []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"}, maxProxies: 2, wantClientIndex: 1, wantTrustedCount: 1, wantTrustedIndices: []int{2}},
		{name: "two trusted proxies at end", parts: []string{"1.1.1.1", "10.0.0.1", "10.0.0.2"}, maxProxies: 2, wantClientIndex: 0, wantTrustedCount: 2, wantTrustedIndices: []int{2, 1}},
		{name: "no trusted proxies allowed when minimum is zero", parts: []string{"1.1.1.1", "8.8.8.8"}, maxProxies: 2, wantClientIndex: 1, wantTrustedCount: 0, wantTrustedIndices: []int{}},
		{name: "no trusted proxies with minimum requirement", parts: []string{"1.1.1.1", "8.8.8.8"}, minProxies: 1, maxProxies: 2, wantClientIndex: 1, wantTrustedCount: 0, wantErr: ErrNoTrustedProxies, wantTrustedIndices: []int{}},
		{name: "too many trusted proxies", parts: []string{"1.1.1.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"}, maxProxies: 2, wantClientIndex: 0, wantTrustedCount: 3, wantErr: ErrTooManyTrustedProxies, wantTrustedIndices: []int{3, 2, 1}},
		{name: "below min proxies", parts: []string{"1.1.1.1", "10.0.0.1"}, minProxies: 2, maxProxies: 3, wantClientIndex: 0, wantTrustedCount: 1, wantErr: ErrTooFewTrustedProxies},
		{name: "mixed trusted and untrusted", parts: []string{"1.1.1.1", "8.8.8.8", "10.0.0.1", "198.51.100.2", "10.0.0.2"}, maxProxies: 3, wantClientIndex: 3, wantTrustedCount: 1, wantTrustedIndices: []int{4}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active := policy
			active.MinTrustedProxies = tt.minProxies
			active.MaxTrustedProxies = tt.maxProxies

			analysis, _, err := analyzeChainRightmost(tt.parts, active, true, parseIP)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("analyzeChainRightmost() error = %v, want nil", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("analyzeChainRightmost() error = %v, want %v", err, tt.wantErr)
			}

			if analysis.ClientIndex != tt.wantClientIndex {
				t.Errorf("clientIndex = %d, want %d", analysis.ClientIndex, tt.wantClientIndex)
			}
			if analysis.TrustedCount != tt.wantTrustedCount {
				t.Errorf("trustedCount = %d, want %d", analysis.TrustedCount, tt.wantTrustedCount)
			}
			if tt.wantErr == nil && tt.wantTrustedIndices != nil {
				if len(analysis.TrustedIndices) != len(tt.wantTrustedIndices) {
					t.Fatalf("trustedIndices length = %d, want %d", len(analysis.TrustedIndices), len(tt.wantTrustedIndices))
				}
				for i, idx := range tt.wantTrustedIndices {
					if analysis.TrustedIndices[i] != idx {
						t.Fatalf("trustedIndices[%d] = %d, want %d", i, analysis.TrustedIndices[i], idx)
					}
				}
			}
		})
	}
}

func TestAnalyzeChainLeftmostWithCIDRs(t *testing.T) {
	policy := proxyPolicy{TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	policy.TrustedProxyMatch = newPrefixMatcher(policy.TrustedProxyCIDRs)

	tests := []struct {
		name             string
		parts            []string
		minProxies       int
		maxProxies       int
		wantClientIndex  int
		wantTrustedCount int
		wantErr          error
	}{
		{name: "one trusted proxy at end", parts: []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"}, maxProxies: 2, wantClientIndex: 0, wantTrustedCount: 1},
		{name: "two trusted proxies at end", parts: []string{"1.1.1.1", "10.0.0.1", "10.0.0.2"}, maxProxies: 2, wantClientIndex: 0, wantTrustedCount: 2},
		{name: "all trusted proxies", parts: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, maxProxies: 3, wantClientIndex: 0, wantTrustedCount: 3},
		{name: "no trusted proxies allowed when minimum is zero", parts: []string{"1.1.1.1", "8.8.8.8"}, maxProxies: 2, wantClientIndex: 0, wantTrustedCount: 0},
		{name: "no trusted proxies with minimum requirement", parts: []string{"1.1.1.1", "8.8.8.8"}, minProxies: 1, maxProxies: 2, wantClientIndex: 0, wantTrustedCount: 0, wantErr: ErrNoTrustedProxies},
		{name: "too many trusted proxies", parts: []string{"1.1.1.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"}, maxProxies: 2, wantClientIndex: 0, wantTrustedCount: 3, wantErr: ErrTooManyTrustedProxies},
		{name: "below min proxies", parts: []string{"1.1.1.1", "10.0.0.1"}, minProxies: 2, maxProxies: 3, wantClientIndex: 0, wantTrustedCount: 1, wantErr: ErrTooFewTrustedProxies},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active := policy
			active.MinTrustedProxies = tt.minProxies
			active.MaxTrustedProxies = tt.maxProxies

			analysis, _, err := analyzeChainLeftmost(tt.parts, active, true, parseIP)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("analyzeChainLeftmost() error = %v, want nil", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("analyzeChainLeftmost() error = %v, want %v", err, tt.wantErr)
			}

			if analysis.ClientIndex != tt.wantClientIndex {
				t.Errorf("clientIndex = %d, want %d", analysis.ClientIndex, tt.wantClientIndex)
			}
			if analysis.TrustedCount != tt.wantTrustedCount {
				t.Errorf("trustedCount = %d, want %d", analysis.TrustedCount, tt.wantTrustedCount)
			}
		})
	}
}
