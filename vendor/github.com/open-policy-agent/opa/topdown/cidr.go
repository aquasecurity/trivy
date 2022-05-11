package topdown

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"

	"github.com/open-policy-agent/opa/ast"
	cidrMerge "github.com/open-policy-agent/opa/internal/cidr/merge"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

func getNetFromOperand(v ast.Value) (*net.IPNet, error) {
	subnetStringA, err := builtins.StringOperand(v, 1)
	if err != nil {
		return nil, err
	}

	_, cidrnet, err := net.ParseCIDR(string(subnetStringA))
	if err != nil {
		return nil, err
	}

	return cidrnet, nil
}

func getLastIP(cidr *net.IPNet) (net.IP, error) {
	prefixLen, bits := cidr.Mask.Size()
	if prefixLen == 0 && bits == 0 {
		// non-standard mask, see https://golang.org/pkg/net/#IPMask.Size
		return nil, fmt.Errorf("CIDR mask is in non-standard format")
	}
	var lastIP []byte
	if prefixLen == bits {
		// Special case for single ip address ranges ex: 192.168.1.1/32
		// We can just use the starting IP as the last IP
		lastIP = cidr.IP
	} else {
		// Use big.Int's so we can handle ipv6 addresses
		firstIPInt := new(big.Int)
		firstIPInt.SetBytes(cidr.IP)
		hostLen := uint(bits) - uint(prefixLen)
		lastIPInt := big.NewInt(1)
		lastIPInt.Lsh(lastIPInt, hostLen)
		lastIPInt.Sub(lastIPInt, big.NewInt(1))
		lastIPInt.Or(lastIPInt, firstIPInt)

		ipBytes := lastIPInt.Bytes()
		lastIP = make([]byte, bits/8)

		// Pack our IP bytes into the end of the return array,
		// since big.Int.Bytes() removes front zero padding.
		for i := 1; i <= len(lastIPInt.Bytes()); i++ {
			lastIP[len(lastIP)-i] = ipBytes[len(ipBytes)-i]
		}
	}

	return lastIP, nil
}

func builtinNetCIDRIntersects(a, b ast.Value) (ast.Value, error) {
	cidrnetA, err := getNetFromOperand(a)
	if err != nil {
		return nil, err
	}

	cidrnetB, err := getNetFromOperand(b)
	if err != nil {
		return nil, err
	}

	// If either net contains the others starting IP they are overlapping
	cidrsOverlap := cidrnetA.Contains(cidrnetB.IP) || cidrnetB.Contains(cidrnetA.IP)

	return ast.Boolean(cidrsOverlap), nil
}

func builtinNetCIDRContains(a, b ast.Value) (ast.Value, error) {
	cidrnetA, err := getNetFromOperand(a)
	if err != nil {
		return nil, err
	}

	// b could be either an IP addressor CIDR string, try to parse it as an IP first, fall back to CIDR
	bStr, err := builtins.StringOperand(b, 1)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(string(bStr))
	if ip != nil {
		return ast.Boolean(cidrnetA.Contains(ip)), nil
	}

	// It wasn't an IP, try and parse it as a CIDR
	cidrnetB, err := getNetFromOperand(b)
	if err != nil {
		return nil, fmt.Errorf("not a valid textual representation of an IP address or CIDR: %s", string(bStr))
	}

	// We can determine if cidr A contains cidr B if and only if A contains
	// the starting address of B and the last address in B.
	cidrContained := false
	if cidrnetA.Contains(cidrnetB.IP) {
		// Only spend time calculating the last IP if the starting IP is already verified to be in cidr A
		lastIP, err := getLastIP(cidrnetB)
		if err != nil {
			return nil, err
		}
		cidrContained = cidrnetA.Contains(lastIP)
	}

	return ast.Boolean(cidrContained), nil
}

var errNetCIDRContainsMatchElementType = errors.New("element must be string or non-empty array")

func getCIDRMatchTerm(a *ast.Term) (*ast.Term, error) {
	switch v := a.Value.(type) {
	case ast.String:
		return a, nil
	case *ast.Array:
		if v.Len() == 0 {
			return nil, errNetCIDRContainsMatchElementType
		}
		return v.Elem(0), nil
	default:
		return nil, errNetCIDRContainsMatchElementType
	}
}

func evalNetCIDRContainsMatchesOperand(operand int, a *ast.Term, iter func(cidr, index *ast.Term) error) error {
	switch v := a.Value.(type) {
	case ast.String:
		return iter(a, a)
	case *ast.Array:
		for i := 0; i < v.Len(); i++ {
			cidr, err := getCIDRMatchTerm(v.Elem(i))
			if err != nil {
				return fmt.Errorf("operand %v: %v", operand, err)
			}
			if err := iter(cidr, ast.IntNumberTerm(i)); err != nil {
				return err
			}
		}
		return nil
	case ast.Set:
		return v.Iter(func(x *ast.Term) error {
			cidr, err := getCIDRMatchTerm(x)
			if err != nil {
				return fmt.Errorf("operand %v: %v", operand, err)
			}
			return iter(cidr, x)
		})
	case ast.Object:
		return v.Iter(func(k, v *ast.Term) error {
			cidr, err := getCIDRMatchTerm(v)
			if err != nil {
				return fmt.Errorf("operand %v: %v", operand, err)
			}
			return iter(cidr, k)
		})
	}
	return nil
}

func builtinNetCIDRContainsMatches(bctx BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	result := ast.NewSet()
	err := evalNetCIDRContainsMatchesOperand(1, args[0], func(cidr1 *ast.Term, index1 *ast.Term) error {
		return evalNetCIDRContainsMatchesOperand(2, args[1], func(cidr2 *ast.Term, index2 *ast.Term) error {
			if v, err := builtinNetCIDRContains(cidr1.Value, cidr2.Value); err != nil {
				return err
			} else if vb, ok := v.(ast.Boolean); ok && bool(vb) {
				result.Add(ast.ArrayTerm(index1, index2))
			}
			return nil
		})
	})
	if err == nil {
		return iter(ast.NewTerm(result))
	}
	return err
}

func builtinNetCIDRExpand(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {

	s, err := builtins.StringOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	ip, ipNet, err := net.ParseCIDR(string(s))
	if err != nil {
		return err
	}

	result := ast.NewSet()

	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {

		if bctx.Cancel != nil && bctx.Cancel.Cancelled() {
			return Halt{
				Err: &Error{
					Code:    CancelErr,
					Message: "net.cidr_expand: timed out before generating all IP addresses",
				},
			}
		}

		result.Add(ast.StringTerm(ip.String()))
	}

	return iter(ast.NewTerm(result))
}

type cidrBlockRange struct {
	First   *net.IP
	Last    *net.IP
	Network *net.IPNet
}

type cidrBlockRanges []*cidrBlockRange

// Implement Sort interface
func (c cidrBlockRanges) Len() int {
	return len(c)
}

func (c cidrBlockRanges) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c cidrBlockRanges) Less(i, j int) bool {
	// Compare last IP.
	cmp := bytes.Compare(*c[i].Last, *c[j].Last)
	if cmp < 0 {
		return true
	} else if cmp > 0 {
		return false
	}

	// Then compare first IP.
	cmp = bytes.Compare(*c[i].First, *c[i].First)
	if cmp < 0 {
		return true
	} else if cmp > 0 {
		return false
	}

	// Ranges are Equal.
	return false
}

// builtinNetCIDRMerge merges the provided list of IP addresses and subnets into the smallest possible list of CIDRs.
// It merges adjacent subnets where possible, those contained within others and also removes any duplicates.
// Original Algorithm: https://github.com/netaddr/netaddr.
func builtinNetCIDRMerge(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	networks := []*net.IPNet{}

	switch v := operands[0].Value.(type) {
	case *ast.Array:
		for i := 0; i < v.Len(); i++ {
			network, err := generateIPNet(v.Elem(i))
			if err != nil {
				return err
			}
			networks = append(networks, network)
		}
	case ast.Set:
		err := v.Iter(func(x *ast.Term) error {
			network, err := generateIPNet(x)
			if err != nil {
				return err
			}
			networks = append(networks, network)
			return nil
		})
		if err != nil {
			return err
		}
	default:
		return errors.New("operand must be an array")
	}

	merged := evalNetCIDRMerge(networks)

	result := ast.NewSet()
	for _, network := range merged {
		result.Add(ast.StringTerm(network.String()))
	}

	return iter(ast.NewTerm(result))
}

func evalNetCIDRMerge(networks []*net.IPNet) []*net.IPNet {
	if len(networks) == 0 {
		return nil
	}

	var ranges cidrBlockRanges

	// For each CIDR, create an IP range. Sort them and merge when possible.
	for _, network := range networks {
		firstIP, lastIP := cidrMerge.GetAddressRange(*network)
		ranges = append(ranges, &cidrBlockRange{
			First:   &firstIP,
			Last:    &lastIP,
			Network: network,
		})
	}

	// merge CIDRs.
	merged := mergeCIDRs(ranges)

	// convert ranges into an equivalent list of net.IPNet.
	result := []*net.IPNet{}

	for _, r := range merged {
		// Not merged with any other CIDR.
		if r.Network != nil {
			result = append(result, r.Network)
		} else {
			// Find new network that represents the merged range.
			rangeCIDRs := cidrMerge.RangeToCIDRs(*r.First, *r.Last)
			result = append(result, rangeCIDRs...)
		}
	}
	return result
}

func generateIPNet(term *ast.Term) (*net.IPNet, error) {
	e, ok := term.Value.(ast.String)
	if !ok {
		return nil, errors.New("element must be string")
	}

	// try to parse element as an IP first, fall back to CIDR
	ip := net.ParseIP(string(e))
	if ip == nil {
		_, network, err := net.ParseCIDR(string(e))
		return network, err
	}

	if ip.To4() != nil {
		return &net.IPNet{
			IP:   ip,
			Mask: ip.DefaultMask(),
		}, nil
	}
	return nil, errors.New("IPv6 invalid: needs prefix length")
}

func mergeCIDRs(ranges cidrBlockRanges) cidrBlockRanges {
	sort.Sort(ranges)

	// Merge adjacent CIDRs if possible.
	for i := len(ranges) - 1; i > 0; i-- {
		previousIP := cidrMerge.GetPreviousIP(*ranges[i].First)

		// If the previous IP of the current network overlaps
		// with the last IP of the previous network in the
		// list, then merge the two ranges together.
		if bytes.Compare(previousIP, *ranges[i-1].Last) <= 0 {
			var firstIP *net.IP
			if bytes.Compare(*ranges[i-1].First, *ranges[i].First) < 0 {
				firstIP = ranges[i-1].First
			} else {
				firstIP = ranges[i].First
			}

			lastIPRange := make(net.IP, len(*ranges[i].Last))
			copy(lastIPRange, *ranges[i].Last)

			firstIPRange := make(net.IP, len(*firstIP))
			copy(firstIPRange, *firstIP)

			ranges[i-1] = &cidrBlockRange{First: &firstIPRange, Last: &lastIPRange, Network: nil}

			// Delete ranges[i] since merged with the previous.
			ranges = append(ranges[:i], ranges[i+1:]...)
		}
	}
	return ranges
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func init() {
	RegisterFunctionalBuiltin2(ast.NetCIDROverlap.Name, builtinNetCIDRContains)
	RegisterFunctionalBuiltin2(ast.NetCIDRIntersects.Name, builtinNetCIDRIntersects)
	RegisterFunctionalBuiltin2(ast.NetCIDRContains.Name, builtinNetCIDRContains)
	RegisterBuiltinFunc(ast.NetCIDRContainsMatches.Name, builtinNetCIDRContainsMatches)
	RegisterBuiltinFunc(ast.NetCIDRExpand.Name, builtinNetCIDRExpand)
	RegisterBuiltinFunc(ast.NetCIDRMerge.Name, builtinNetCIDRMerge)
}
