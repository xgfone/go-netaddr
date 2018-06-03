package netaddr

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

var (
	uint32Max = uint32(math.MaxUint32)
	uint64Max = uint64(math.MaxUint64)

	ipv4MaxBit = 32
	ipv6MaxBit = 128

	ipv4MaxMask []byte
	ipv6MaxMask []byte

	ipv4HostMaskMap    map[int][]byte
	ipv4NetworkMaskMap map[int][]byte
	ipv6HostMaskMap    map[int][]byte
	ipv6NetworkMaskMap map[int][]byte
)

func init() {
	tmp1 := uint32ToBytes(uint32Max)
	ipv4MaxMask = tmp1[:]
	tmp2 := uint64ToBytes(uint64Max, uint64Max)
	ipv6MaxMask = tmp2[:]

	ipv4HostMaskMap = make(map[int][]byte, 33)
	ipv4NetworkMaskMap = make(map[int][]byte, 33)
	for i := 0; i <= ipv4MaxBit; i++ {
		host := uint32Max >> uint32(i)
		net := ^host

		_host := uint32ToBytes(host)
		_net := uint32ToBytes(net)
		ipv4NetworkMaskMap[i] = _net[:]
		ipv4HostMaskMap[i] = _host[:]
	}

	ipv6HostMaskMap = make(map[int][]byte, 129)
	ipv6NetworkMaskMap = make(map[int][]byte, 129)
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

		host := uint64ToBytes(host1, host2)
		net := uint64ToBytes(net1, net2)

		ipv6NetworkMaskMap[i] = host[:]
		ipv6HostMaskMap[i] = net[:]
	}
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

// IPv4 Network
var (
	IPv46To4      = MustNewIPNetwork("192.88.99.0/24") //6to4 anycast relays (RFC 3068)
	IPv4Loopback  = MustNewIPNetwork("127.0.0.0/8")    // Loopback addresses (RFC 990)
	IPv4LinkLocal = MustNewIPNetwork("169.254.0.0/16")
	IPv4Multicast = MustNewIPNetwork("224.0.0.0/4")

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
	IPv6Loopback  = MustNewIPNetwork("::1/128")
	IPv6LinkLocal = MustNewIPNetwork("fe80::/10")
	IPv6Multicast = MustNewIPNetwork("ff00::/8")

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
}

// NewIPNetworkFromIPAddress returns a new IPNetwork by IPAddress.
func NewIPNetworkFromIPAddress(ip IPAddress, mask int) (IPNetwork, error) {
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

	return IPNetwork{ip: ip, mask: mask}, nil
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
func NewIPNetwork(ipnet string) (IPNetwork, error) {
	index := strings.IndexByte(ipnet, '/')
	if index == -1 {
		return IPNetwork{}, fmt.Errorf("invalid IPv4/IPv6 network address %s", ipnet)
	}
	mask, err := strconv.ParseInt(ipnet[index+1:], 10, 16)
	if err != nil {
		return IPNetwork{}, err
	}

	ip, err := NewIPAddress(ipnet[:index])
	if err != nil {
		return IPNetwork{}, err
	}

	return NewIPNetworkFromIPAddress(ip, int(mask))
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
func (net IPNetwork) String() string {
	return fmt.Sprintf("%s/%d", net.ip.String(), net.mask)
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

// Network returns the network address.
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
	bs := bytesXor(getMaxMask(net.ip.version), getHostMask(net.ip.version, net.mask))
	bs = bytesAnd(net.ip.Bytes(), bs)
	ip, _ := NewIPAddress(bs)
	return ip
}

// Last returns the last ip address of the network.
func (net IPNetwork) Last() IPAddress {
	bs := bytesOr(net.ip.Bytes(), getHostMask(net.ip.version, net.mask))
	ip, _ := NewIPAddress(bs)
	return ip
}

// CIDR returns the true CIDR address for the network which omits any host bits
// to the right of the CIDR subnet prefix.
func (net IPNetwork) CIDR() IPNetwork {
	bs := bytesAnd(net.ip.Bytes(), getNetworkMask(net.ip.version, net.mask))
	ip, _ := NewIPAddress(bs)
	cidr, _ := NewIPNetworkFromIPAddress(ip, net.mask)
	return cidr
}

// HasIP reports whether the network contains this ip address.
func (net IPNetwork) HasIP(ip IPAddress) bool {
	if ip.version != net.ip.version {
		return false
	}

	first := net.First().Value()
	last := net.Last().Value()
	value := ip.Value()
	if first <= value && value <= last {
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
	first := net.First().Value()
	last := net.Last().Value()
	for i := first; i <= last; i++ {
		ip, err := NewIPAddress(i, version)
		if err != nil {
			panic(err)
		}
		f(ip)
	}
}
