package netaddr

import (
	"fmt"
	"math"
	"net"
	"strings"
)

// IPAddress represents a IPv4/IPv6 address.
type IPAddress struct {
	ip      net.IP
	version int
}

// NewIPAddressByUint64 returns a new IPAddress by uint64.
//
// If the second argument exists, it represents that the ip addres is a IPv6,
// or IPv4.
func NewIPAddressByUint64(v1 uint64, v2 ...uint64) IPAddress {
	// IPv4
	if len(v2) == 0 {
		bs := uint32ToBytes(uint32(v1))
		return IPAddress{ip: net.IPv4(bs[0], bs[1], bs[2], bs[3]).To4(), version: 4}
	}

	// IPv6
	bs := uint64ToBytes(v1, v2[0])
	return IPAddress{ip: net.IP(bs[:]), version: 6}
}

// NewIPAddress returns a new IPAddress.
//
// The argument, ip, maybe a string, []byte, [4]byte, [6]byte, float64 or net.IP
// representation of IPv4 or IPv6. Except for float64 and net.IP, version is
// optional for other types.
func NewIPAddress(ip interface{}, version ...int) (IPAddress, error) {
	var _ip net.IP
	var _version int

	if len(version) > 0 {
		_version = version[0]
		if _version != 4 && _version != 6 {
			return IPAddress{}, fmt.Errorf("version must be 4 or 6")
		}
	}

	switch ip.(type) {
	case string:
		v := ip.(string)
		if _ip = net.ParseIP(v); _ip == nil {
			return IPAddress{}, fmt.Errorf("'%s' is not a valid ipv4/ipv6", ip)
		}
		if _version == 0 {
			if strings.Contains(v, ":") {
				_version = 6
			} else {
				_version = 4
			}
		}
	case []byte:
		bs := ip.([]byte)
		switch len(bs) {
		case net.IPv4len:
			_version = 4
			_ip = net.IPv4(bs[0], bs[1], bs[2], bs[3])
		case net.IPv6len:
			_version = 6
			_ip = net.IP(bs)
		default:
			return IPAddress{}, fmt.Errorf("the length of []byte must be 4 or 16")
		}
	case [4]byte:
		_version = 4
		bs := ip.([4]byte)
		_ip = net.IPv4(bs[0], bs[1], bs[2], bs[3])
	case [16]byte:
		_version = 6
		bs := ip.([16]byte)
		_ip = net.IP(bs[:])
	case float64:
		if _version == 0 {
			return IPAddress{}, fmt.Errorf("missing the argument 'version'")
		}
		f := ip.(float64)
		switch _version {
		case 4:
			return NewIPAddressByUint64(uint64(f)), nil
		case 6:
			v := float64(uint64Max)
			v1 := uint64(f / v)
			v2 := uint64(math.Mod(f, v))
			return NewIPAddressByUint64(v1, v2), nil
		}
	case net.IP:
		if _version == 0 {
			return IPAddress{}, fmt.Errorf("missing the argument 'version'")
		}
		_ip = ip.(net.IP)
	default:
		return IPAddress{}, fmt.Errorf("does not support the type '%T'", ip)
	}

	addr := IPAddress{ip: _ip, version: _version}
	if addr.version == 4 {
		addr = addr.IPv4()
	} else if addr.version == 6 {
		addr = addr.IPv6()
	}
	return addr, nil
}

// MustNewIPAddress is the same as NewIPAddress, but panic if an error occurs.
func MustNewIPAddress(ip interface{}, version ...int) IPAddress {
	addr, err := NewIPAddress(ip, version...)
	if err != nil {
		panic(err)
	}
	return addr
}

// IsValid reports whether the ip address is valid.
func (ip IPAddress) IsValid() bool {
	v := ip.version
	_len := len(ip.ip)
	return (v == 4 && _len == 4) || (v == 6 && _len == 16) || false
}

// String returns a string representation of the ip address.
func (ip IPAddress) String() string {
	return ip.ip.String()
}

// Bytes returns a []byte representation of the ip address.
func (ip IPAddress) Bytes() []byte {
	return []byte(ip.ip)
}

// Version returns the version of ip.
func (ip IPAddress) Version() int {
	return ip.version
}

// IP converts the ip to the type, net.IP.
func (ip IPAddress) IP() net.IP {
	return ip.ip
}

// IPv4 returns a new IPv4 IPAddress.
func (ip IPAddress) IPv4() IPAddress {
	return IPAddress{ip: ip.ip.To4(), version: 4}
}

// IPv6 returns a new IPv6 IPAddress.
func (ip IPAddress) IPv6() IPAddress {
	return IPAddress{ip: ip.ip.To16(), version: 6}
}

// IPv4Value returns an 32-bit integer of ip. But it returns uint64 as the type.
//
// If the ip address is IPv6, it will return 0.
func (ip IPAddress) IPv4Value() uint64 {
	if ip.version == 6 {
		return 0
	}
	return ipv4ToUint64(ip.ip[:4])
}

// IPv6Value returns two 64-bit integers of ipv4.
//
// The first value is the first 64 bits, and the last is the last 64 bits.
//
// If the ip address is IPv4, it will return (0, 0).
func (ip IPAddress) IPv6Value() (uint64, uint64) {
	if ip.version == 4 {
		return 0, 0
	}
	return ipv6ToUint64(ip.ip[:16])
}

// Value returns the 64-bit float representation of the ipv4/ipv6 address.
func (ip IPAddress) Value() float64 {
	switch ip.version {
	case 4:
		return float64(ip.IPv4Value())
	case 6:
		v1, v2 := ip.IPv6Value()
		return float64(v1)*float64(uint64Max) + float64(v2)
	}
	return 0
}

// IsEqual reports whether ip is equal to other.
func (ip IPAddress) IsEqual(other IPAddress) bool {
	return ip.ip.Equal(other.ip)
}

// IsUnspecified reports whether ip is an unspecified address, either
// the IPv4 address "0.0.0.0" or the IPv6 address "::".
func (ip IPAddress) IsUnspecified() bool {
	return ip.ip.IsUnspecified()
}

// IsInterfaceLocalMulticast reports whether ip is
// an interface-local multicast address. that's, ff01::/16.
func (ip IPAddress) IsInterfaceLocalMulticast() bool {
	return ip.ip.IsInterfaceLocalMulticast()
}

// IsLinkLocalMulticast reports whether ip is a link-local multicast address,
// that's, 224.0.0.0/24 or ff02::/16.
func (ip IPAddress) IsLinkLocalMulticast() bool {
	return ip.ip.IsLinkLocalMulticast()
}

// IsLinkLocalUnicast reports whether ip is a link-local unicast address,
// that's, 169.254.0.0/16 or fe80::/10.
func (ip IPAddress) IsLinkLocalUnicast() bool {
	return ip.ip.IsLinkLocalUnicast()
}

// IsGlobalUnicast reports whether ip is a global unicast
// address.
//
// The identification of global unicast addresses uses address type
// identification as defined in RFC 1122, RFC 4632 and RFC 4291 with
// the exception of IPv4 directed broadcast addresses.
// It returns true even if ip is in IPv4 private address space or
// local IPv6 unicast address space.
//
// They are not
//    0.0.0.0  255.255.255.255  127.0.0.0/8  169.254.0.0/16  224.0.0.0/4
//    ::  ::1  fe80::/10  ff00::/8
func (ip IPAddress) IsGlobalUnicast() bool {
	return ip.ip.IsGlobalUnicast()
}

// IsUnicast reports whether the ip address is the unicast
func (ip IPAddress) IsUnicast() bool {
	return !ip.IsMulticast()
}

// IsMulticast reports whether the ip address is the multicast,
// that's, 224.0.0.0/4 or ff00::/8.
func (ip IPAddress) IsMulticast() bool {
	return ip.ip.IsMulticast()
}

// IsLoopback reports whether the ip address is the loopback,
// that's, 127.0.0.1/8 or ::1.
func (ip IPAddress) IsLoopback() bool {
	return ip.ip.IsLoopback()
}
