package clientip

import "net/netip"

type trustedProxyMatcher struct {
	initialized bool
	ipv4Root    *prefixTrieNode
	ipv6Root    *prefixTrieNode
}

type prefixTrieNode struct {
	children [2]*prefixTrieNode
	terminal bool
}

func buildTrustedProxyMatcher(prefixes []netip.Prefix) trustedProxyMatcher {
	matcher := trustedProxyMatcher{}
	if len(prefixes) == 0 {
		return matcher
	}

	matcher.initialized = true

	for _, prefix := range prefixes {
		addr := prefix.Addr()
		if !addr.IsValid() {
			continue
		}

		bits := prefix.Bits()
		if bits < 0 {
			continue
		}
		if bits > addr.BitLen() {
			bits = addr.BitLen()
		}

		if addr.Is4() {
			if matcher.ipv4Root == nil {
				matcher.ipv4Root = &prefixTrieNode{}
			}

			bytes := addr.As4()
			insertPrefix(matcher.ipv4Root, bytes[:], bits)
			continue
		}

		if matcher.ipv6Root == nil {
			matcher.ipv6Root = &prefixTrieNode{}
		}

		bytes := addr.As16()
		insertPrefix(matcher.ipv6Root, bytes[:], bits)
	}

	return matcher
}

func insertPrefix(root *prefixTrieNode, addr []byte, bits int) {
	node := root
	if bits == 0 {
		node.terminal = true
		return
	}

	for bitIndex := 0; bitIndex < bits; bitIndex++ {
		bit := addrBit(addr, bitIndex)
		child := node.children[bit]
		if child == nil {
			child = &prefixTrieNode{}
			node.children[bit] = child
		}
		node = child
	}

	node.terminal = true
}

func (m trustedProxyMatcher) contains(ip netip.Addr) bool {
	if !m.initialized || !ip.IsValid() {
		return false
	}

	if ip.Is4() {
		if m.ipv4Root == nil {
			return false
		}

		bytes := ip.As4()
		return trieContains(m.ipv4Root, bytes[:])
	}

	if m.ipv6Root == nil {
		return false
	}

	bytes := ip.As16()
	return trieContains(m.ipv6Root, bytes[:])
}

func trieContains(root *prefixTrieNode, addr []byte) bool {
	node := root
	if node == nil {
		return false
	}

	if node.terminal {
		return true
	}

	for bitIndex := range len(addr) * 8 {
		node = node.children[addrBit(addr, bitIndex)]
		if node == nil {
			return false
		}
		if node.terminal {
			return true
		}
	}

	return false
}

func addrBit(addr []byte, bitIndex int) int {
	byteIndex := bitIndex / 8
	shift := uint(7 - (bitIndex % 8))
	if ((addr[byteIndex] >> shift) & 1) == 1 {
		return 1
	}
	return 0
}
