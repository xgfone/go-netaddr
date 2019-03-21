// Copyright 2018 xgfone
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netaddr

import (
	"fmt"
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)

	uint32Max = uint32(math.MaxUint32)
	uint64Max = uint64(math.MaxUint64)

	ipv4MaxBit = 32
	ipv6MaxBit = 128

	_ipv4MaxMask = uint32ToBytes(uint32Max)
	_ipv6MaxMask = uint64ToBytes(uint64Max, uint64Max)
	ipv4MaxMask  = _ipv4MaxMask[:]
	ipv6MaxMask  = _ipv6MaxMask[:]

	ipv4HostMaskMap    = initIPv4HostMaskMap()
	ipv4NetworkMaskMap = initIPv4NetworkMaskMap()
	ipv6HostMaskMap    = initIPv6HostMaskMap()
	ipv6NetworkMaskMap = initIPv6NetworkMaskMap()

	exps = initExps()
)

func initIPv4HostMaskMap() map[int][]byte {
	ipv4HostMaskMap := make(map[int][]byte, 33)
	for i := 0; i <= ipv4MaxBit; i++ {
		_host := uint32ToBytes(uint32Max >> uint32(i))
		ipv4HostMaskMap[i] = _host[:]
	}
	return ipv4HostMaskMap
}

func initIPv4NetworkMaskMap() map[int][]byte {
	ipv4NetworkMaskMap := make(map[int][]byte, 33)
	for i := 0; i <= ipv4MaxBit; i++ {
		host := uint32Max >> uint32(i)
		net := uint32ToBytes(^host)
		ipv4NetworkMaskMap[i] = net[:]
	}
	return ipv4NetworkMaskMap
}

func initIPv6HostMaskMap() map[int][]byte {
	ipv6HostMaskMap := make(map[int][]byte, 129)
	for i := 0; i <= ipv6MaxBit; i++ {
		var host1, host2 uint64
		if i < 64 {
			host1 = uint64Max >> uint64(i)
			host2 = uint64Max
		} else {
			host1 = 0
			host2 = uint64Max >> uint64(i-64)
		}

		host := uint64ToBytes(host1, host2)
		ipv6HostMaskMap[i] = host[:]
	}
	return ipv6HostMaskMap
}

func initIPv6NetworkMaskMap() map[int][]byte {
	ipv6NetworkMaskMap := make(map[int][]byte, 129)
	for i := 0; i <= ipv6MaxBit; i++ {
		var net1, net2, host1, host2 uint64
		if i < 64 {
			host1 = uint64Max >> uint64(i)
			host2 = uint64Max
			net1 = ^host1
			net2 = 0
		} else {
			host1 = 0
			host2 = uint64Max >> uint64(i-64)
			net1 = uint64Max
			net2 = ^host2
		}

		net := uint64ToBytes(net1, net2)
		ipv6NetworkMaskMap[i] = net[:]
	}
	return ipv6NetworkMaskMap
}

func initExps() map[int]*big.Int {
	exps := make(map[int]*big.Int, 129)
	for i := 0; i <= ipv6MaxBit; i++ {
		exps[i] = big.NewInt(0).Exp(two, big.NewInt(int64(i)), nil)
	}
	return exps
}

func getHostMask(version, mask int) []byte {
	switch version {
	case 4:
		return ipv4HostMaskMap[mask]
	case 6:
		return ipv6HostMaskMap[mask]
	}
	return nil
}

func getNetworkMask(version, mask int) []byte {
	switch version {
	case 4:
		return ipv4NetworkMaskMap[mask]
	case 6:
		return ipv6NetworkMaskMap[mask]
	}
	return nil
}

func getMaxMask(version int) []byte {
	switch version {
	case 4:
		return ipv4MaxMask
	case 6:
		return ipv6MaxMask
	}
	return nil
}

func getExpMask(version, mask int) *big.Int {
	switch version {
	case 4:
		return exps[ipv4MaxBit-mask]
	case 6:
		return exps[ipv6MaxBit-mask]
	}
	return nil
}

// IPv4 Network
var (
	IPv46To4      = MustNewIPNetwork("192.88.99.0/24") // 6to4 anycast relays (RFC 3068)
	IPv4Loopback  = MustNewIPNetwork("127.0.0.0/8")    // Loopback addresses (RFC 990)
	IPv4LinkLocal = MustNewIPNetwork("169.254.0.0/16") // Link-Local unicast address (RFC 3927)
	IPv4Multicast = MustNewIPNetwork("224.0.0.0/4")    // Multicast address (RFC 5771)

	IPv4Private = []IPNetwork{
		MustNewIPNetwork("10.0.0.0/8"),     // Class A private network local communication (RFC 1918)
		MustNewIPNetwork("100.64.0.0/10"),  // Carrier grade NAT (RFC 6598)
		MustNewIPNetwork("172.16.0.0/12"),  // Private network - local communication (RFC 1918)
		MustNewIPNetwork("192.0.0.0/24"),   // IANA IPv4 Special Purpose Address Registry (RFC 5736)
		MustNewIPNetwork("192.168.0.0/16"), // Class B private network local communication (RFC 1918)
		MustNewIPNetwork("198.18.0.0/15"),  // Testing of inter-network communications between subnets (RFC 2544)
		MustNewIPNetwork("239.0.0.0/8"),    // Administrative Multicast
	}

	IPv4Reserved = []IPNetwork{
		MustNewIPNetwork("0.0.0.0/8"),       // Broadcast message (RFC 1700)
		MustNewIPNetwork("192.0.2.0/24"),    // TEST-NET examples and documentation (RFC 5737)
		MustNewIPNetwork("240.0.0.0/4"),     // Reserved for  multicast assignments (RFC 5771)
		MustNewIPNetwork("198.51.100.0/24"), // TEST-NET-2 examples and documentation (RFC 5737)
		MustNewIPNetwork("203.0.113.0/24"),  // TEST-NET-3 examples and documentation (RFC 5737)

		// Reserved Multicast
		MustNewIPNetwork("233.252.0.0/24"), // Multicast test network
		MustNewIPNetwork("234.0.0.0/8"),
		MustNewIPNetwork("235.0.0.0/8"),
		MustNewIPNetwork("236.0.0.0/8"),
		MustNewIPNetwork("237.0.0.0/8"),
		MustNewIPNetwork("238.0.0.0/8"),
		MustNewIPNetwork("225.0.0.0/8"),
		MustNewIPNetwork("226.0.0.0/8"),
		MustNewIPNetwork("227.0.0.0/8"),
		MustNewIPNetwork("228.0.0.0/8"),
		MustNewIPNetwork("229.0.0.0/8"),
		MustNewIPNetwork("230.0.0.0/8"),
		MustNewIPNetwork("231.0.0.0/8"),

		IPv4Loopback,
		IPv46To4,
	}
)

// IPv6 Network
var (
	IPv6Loopback  = MustNewIPNetwork("::1/128")   // Loopback address
	IPv6LinkLocal = MustNewIPNetwork("fe80::/10") // Link-Local unicast address
	IPv6Multicast = MustNewIPNetwork("ff00::/8")  // Multicast address

	IPv6Private = []IPNetwork{
		MustNewIPNetwork("fc00::/7"),  // Unique Local Addresses (ULA)
		MustNewIPNetwork("fec0::/10"), // Site Local Addresses (deprecated - RFC 3879)
	}

	IPv6Reserved = []IPNetwork{
		MustNewIPNetwork("::/8"),
		MustNewIPNetwork("0100::/8"),
		MustNewIPNetwork("0200::/7"),
		MustNewIPNetwork("0400::/6"),
		MustNewIPNetwork("0800::/5"),
		MustNewIPNetwork("1000::/4"),
		MustNewIPNetwork("4000::/3"),
		MustNewIPNetwork("6000::/3"),
		MustNewIPNetwork("8000::/3"),
		MustNewIPNetwork("a000::/3"),
		MustNewIPNetwork("c000::/3"),
		MustNewIPNetwork("e000::/4"),
		MustNewIPNetwork("f000::/5"),
		MustNewIPNetwork("f800::/6"),
		MustNewIPNetwork("fe00::/9"),
		MustNewIPNetwork("ff00::/12"),
	}
)

// IsPrivate reports whether the ip address is the private.
func (ip IPAddress) IsPrivate() bool {
	if ip.version == 4 {
		for _, cidr := range IPv4Private {
			if cidr.HasIP(ip) {
				return true
			}
		}
	} else if ip.version == 6 {
		for _, cidr := range IPv6Private {
			if cidr.HasIP(ip) {
				return true
			}
		}
	}

	return ip.IsLinkLocalUnicast()
}

// IsReserved reports whether the ip address is the reserved.
func (ip IPAddress) IsReserved() bool {
	if ip.version == 4 {
		for _, cidr := range IPv4Reserved {
			if cidr.HasIP(ip) {
				return true
			}
		}
	} else if ip.version == 6 {
		for _, cidr := range IPv6Reserved {
			if cidr.HasIP(ip) {
				return true
			}
		}
	}

	return false
}

// IPNetwork represents a IPv4/IPv6 network.
type IPNetwork struct {
	mask int
	ip   IPAddress

	last  IPAddress
	first IPAddress
}

// NewIPNetworkFromIPAddress returns a new IPNetwork by IPAddress.
func NewIPNetworkFromIPAddress(ip IPAddress, mask int) (net IPNetwork, err error) {
	switch ip.version {
	case 4:
		if mask < 0 || mask > 32 {
			return IPNetwork{}, fmt.Errorf("mask must be between 0 and 32")
		}
	case 6:
		if mask < 0 || mask > 128 {
			return IPNetwork{}, fmt.Errorf("mask must be between 0 and 128")
		}
	default:
		return IPNetwork{}, fmt.Errorf("version must be 4 or 6")
	}

	net = IPNetwork{ip: ip, mask: mask}
	net.first = net.getFirst()
	net.last = net.getLast()
	return net, nil
}

// NewIPNetworkFromIP returns a new IPNetwork by net.IP.
func NewIPNetworkFromIP(ip net.IP, version int, mask int) (IPNetwork, error) {
	if ip == nil {
		return IPNetwork{}, fmt.Errorf("ip is nil")
	}

	_ip, err := NewIPAddress(ip, version)
	if err != nil {
		return IPNetwork{}, err
	}

	return NewIPNetworkFromIPAddress(_ip, mask)
}

// NewIPNetwork returns a new IPNetwork.
//
// Change 0.2.0: the subnet mask is optional.
// The default is 32 for IPv4, and 128 for IPv6.
func NewIPNetwork(ipnet string) (IPNetwork, error) {
	var mask int
	index := strings.IndexByte(ipnet, '/')
	if index == -1 {
		index = len(ipnet)
		if strings.IndexByte(ipnet, ':') == -1 {
			mask = 32
		} else {
			mask = 128
		}
	} else {
		_mask, err := strconv.ParseInt(ipnet[index+1:], 10, 16)
		if err != nil {
			return IPNetwork{}, err
		}
		mask = int(_mask)
	}

	ip, err := NewIPAddress(ipnet[:index])
	if err != nil {
		return IPNetwork{}, err
	}

	return NewIPNetworkFromIPAddress(ip, mask)
}

// MustNewIPNetwork is the same as NewIPNetwork, but panic if an error occurs.
func MustNewIPNetwork(ipnet string) IPNetwork {
	net, err := NewIPNetwork(ipnet)
	if err != nil {
		panic(err)
	}
	return net
}

// String returns a string representation of the ip network.
//
// It will return "" if the network is invalid.
func (net IPNetwork) String() string {
	if net.ip.IsValid() {
		return fmt.Sprintf("%s/%d", net.ip.String(), net.mask)
	}
	return ""
}

// Version returns the version of the network.
func (net IPNetwork) Version() int {
	return net.ip.version
}

// Mask returns the size of the subnet mask.
func (net IPNetwork) Mask() int {
	return net.mask
}

// Size returns the number of the hosts in the network.
func (net IPNetwork) Size() float64 {
	switch net.ip.version {
	case 4:
		v := 1 << (uint(ipv4MaxBit) - uint(net.mask))
		return float64(v)
	case 6:
		return math.Pow(2, float64(ipv6MaxBit-net.mask))
	}
	return 0
}

// Address returns the IP address.
func (net IPNetwork) Address() IPAddress {
	return net.ip
}

// Network returns the ip address.
func (net IPNetwork) Network() IPAddress {
	bs := bytesAnd(net.ip.Bytes(), getNetworkMask(net.ip.version, net.mask))
	ip, _ := NewIPAddress(bs)
	return ip
}

// Broadcast returns the broadcast address.
func (net IPNetwork) Broadcast() IPAddress {
	if net.ip.version == 4 && 32-net.mask <= 1 {
		return IPAddress{}
	}
	bs := bytesOr(net.ip.Bytes(), getHostMask(net.ip.version, net.mask))
	ip, _ := NewIPAddress(bs)
	return ip
}

// NetworkMask returns the network mask address of the network.
func (net IPNetwork) NetworkMask() IPAddress {
	bs := bytesXor(getMaxMask(net.ip.version), getHostMask(net.ip.version, net.mask))
	ip, _ := NewIPAddress(bs)
	return ip
}

// HostMask returns the host mask address of the network.
func (net IPNetwork) HostMask() IPAddress {
	ip, _ := NewIPAddress(getHostMask(net.ip.version, net.mask))
	return ip
}

// First returns the first ip address of the network.
func (net IPNetwork) First() IPAddress {
	return net.first
}

func (net IPNetwork) getFirst() IPAddress {
	bs := bytesXor(getMaxMask(net.ip.version), getHostMask(net.ip.version, net.mask))
	bs = bytesAnd(net.ip.Bytes(), bs)
	return MustNewIPAddress(bs)
}

// Last returns the last ip address of the network.
func (net IPNetwork) Last() IPAddress {
	return net.last
}

func (net IPNetwork) getLast() IPAddress {
	bs := bytesOr(net.ip.Bytes(), getHostMask(net.ip.version, net.mask))
	return MustNewIPAddress(bs)
}

// CIDR returns the true CIDR address for the network which omits any host bits
// to the right of the CIDR subnet prefix.
func (net IPNetwork) CIDR() IPNetwork {
	bs := bytesAnd(net.ip.Bytes(), getNetworkMask(net.ip.version, net.mask))
	ip, _ := NewIPAddress(bs)
	cidr, _ := NewIPNetworkFromIPAddress(ip, net.mask)
	return cidr
}

func (net IPNetwork) moveNetwork(previous bool) (IPNetwork, error) {
	netmask := getNetworkMask(net.ip.version, net.mask)
	bs := bytesAnd(net.ip.Bytes(), netmask)
	bi := new(big.Int).SetBytes(bs)
	iszero := bi.Cmp(zero) == 0

	if previous {
		bi.Sub(bi, one)
		bs = bytesAnd(bi.Bytes(), netmask)
		if iszero && bytesIsZero(bs) {
			return IPNetwork{}, fmt.Errorf("decrement is less than zero")
		}
	} else {
		bi.Add(bi, getExpMask(net.ip.version, net.mask))
		bs = bytesAnd(bi.Bytes(), netmask)
		if !iszero && bytesIsZero(bs) {
			return IPNetwork{}, fmt.Errorf("increment exceeds address boundary")
		}
	}

	ip, err := NewIPAddress(bs, net.ip.version)
	if err != nil {
		return IPNetwork{}, err
	}
	_net, err := NewIPNetworkFromIPAddress(ip, net.mask)
	if err != nil {
		return IPNetwork{}, err
	}
	return _net, nil
}

// Previous returns the previous network of the current.
func (net IPNetwork) Previous() (IPNetwork, error) {
	return net.moveNetwork(true)
}

// Next returns the next network of the current.
func (net IPNetwork) Next() (IPNetwork, error) {
	return net.moveNetwork(false)
}

// Contains reports whether the network contains the other network,
// that's, other is the subnet of the current network.
func (net IPNetwork) Contains(other IPNetwork) bool {
	if net.ip.version != other.ip.version {
		return false
	}

	if net.first.Compare(other.first) <= 0 && other.first.Compare(net.last) <= 0 {
		return true
	}
	return false
}

// HasIP reports whether the network contains this ip address.
func (net IPNetwork) HasIP(ip IPAddress) bool {
	if ip.version != net.ip.version {
		return false
	}

	if net.first.Compare(ip) <= 0 && ip.Compare(net.last) <= 0 {
		return true
	}
	return false
}

// HasStringIP reports whether the network contains this ip address.
func (net IPNetwork) HasStringIP(ip string) bool {
	_ip, err := NewIPAddress(ip)
	if err != nil {
		return false
	}
	return net.HasIP(_ip)
}

// Walk traverses all the hosts in the network.
//
// Notice: For the more bigger network, please don't traverse it.
func (net IPNetwork) Walk(f func(IPAddress)) {
	version := net.ip.version
	first := net.First().BigInt()
	last := net.Last().BigInt()
	for i := first; i.Cmp(last) <= 0; i.Add(i, one) {
		ip, err := NewIPAddress(i, version)
		if err != nil {
			panic(err)
		}
		f(ip)
	}
}
