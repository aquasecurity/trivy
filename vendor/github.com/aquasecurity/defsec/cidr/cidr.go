package cidr

import (
	"fmt"
	"net"
	"strings"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
		"100.64.0.0/10",  // IPv4 shared address space
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: `%w`", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivate(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// CountAddresses calculates the number of addresses within the given CIDR. If the given
// CIDR is in fact an IP (includes no /), 1 will bne returned. If the number of addresses
// overflows an unsigned 64-bit int, the maximum value of an unsigned 64-bit int will be
// returned.
func CountAddresses(inputCIDR string) uint64 {
	if inputCIDR == "*" || inputCIDR == "internet" || inputCIDR == "any" {
		return 0xffffffffffffffff
	}
	if !strings.Contains(inputCIDR, "/") {
		ip := net.ParseIP(inputCIDR)
		if ip == nil {
			return 0
		}
		return 1
	}
	_, network, err := net.ParseCIDR(inputCIDR)
	if err != nil {
		return 0
	}
	prefixLen, bits := network.Mask.Size()
	power := bits - prefixLen
	if power >= 63 {
		return 0xffffffffffffffff
	}
	return 1 << power
}

// IsPublic returns true if a provided IP is outside of the designated public ranges, or
// true if either of the min/max addresses of a provided CIDR are outside of these ranges.
func IsPublic(cidr string) bool {

	// some providers use wildcards etc. instead of "0.0.0.0/0" :/
	if cidr == "*" || cidr == "internet" || cidr == "any" {
		return true
	}

	// providers also allow "ranges" instead of cidrs :/
	if strings.Contains(cidr, "-") {
		parts := strings.Split(cidr, "-")
		if len(parts) != 2 {
			return false
		}
		if !isPrivate(net.IP(strings.TrimSpace(parts[0]))) {
			return true
		}
		if !isPrivate(net.IP(strings.TrimSpace(parts[1]))) {
			return true
		}
		return false
	}

	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return false
		}
		return !isPrivate(ip)
	}

	start, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	if !isPrivate(start) {
		return true
	}

	end := highestAddress(network)
	return !isPrivate(end)
}

func highestAddress(network *net.IPNet) net.IP {
	raw := make([]byte, len(network.IP))
	copy(raw, network.IP)
	ones, bits := network.Mask.Size()
	flip := bits - ones
	for i := 0; i < flip; i++ {
		index := len(raw) - 1
		index -= (i / 8)
		raw[index] ^= (1 << (i % 8))
	}
	return net.IP(raw)
}
